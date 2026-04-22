#include "crypto/public_key.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <random>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/plaintext.h"
#include "crypto/secret_key.h"
#include "math/context.h"
#include "math/modulus.h"
#include "math/poly.h"
#include "math/representation.h"
#include "math/sample_vec_cbd.h"
#include "util/profiler.h"

// Serialization includes
#include "crypto/serialization/msgpack_adaptors.h"

namespace crypto {
namespace bfv {

namespace {

template <typename RNG>
std::vector<int64_t> SampleTernaryCoefficients(size_t degree, RNG &rng) {
  std::uniform_int_distribution<int> dist(0, 2);
  std::vector<int64_t> coeffs(degree);
  for (size_t i = 0; i < degree; ++i) {
    int sample = dist(rng);
    coeffs[i] = sample == 0 ? -1 : (sample == 1 ? 0 : 1);
  }
  return coeffs;
}

}  // namespace

// PublicKey::Impl - PIMPL implementation
class PublicKey::Impl {
 public:
  std::shared_ptr<BfvParameters> par;
  Ciphertext c;  // The public key ciphertext (encryption of zero)

  Impl() = default;

  // Constructor from parameters and ciphertext
  Impl(std::shared_ptr<BfvParameters> params, Ciphertext ciphertext)
      : par(std::move(params)), c(std::move(ciphertext)) {}
};

// PublicKey implementation
PublicKey::~PublicKey() = default;

PublicKey::PublicKey(const PublicKey &other)
    : pImpl(std::make_unique<Impl>(*other.pImpl)) {}

PublicKey &PublicKey::operator=(const PublicKey &other) {
  if (this != &other) {
    *pImpl = *other.pImpl;
  }
  return *this;
}

PublicKey::PublicKey(PublicKey &&other) noexcept = default;
PublicKey &PublicKey::operator=(PublicKey &&other) noexcept = default;

PublicKey::PublicKey(std::unique_ptr<Impl> impl) : pImpl(std::move(impl)) {}

PublicKey PublicKey::from_secret_key(const SecretKey &secret_key,
                                     std::mt19937_64 &rng) {
  if (secret_key.empty()) {
    throw ParameterException("Secret key is empty");
  }

  try {
    auto params = secret_key.parameters();

    auto zero_encoding = Encoding::poly();
    auto zero_plaintext = Plaintext::zero(zero_encoding, params);

    auto c = secret_key.encrypt(zero_plaintext, rng);
    auto key_polys = c.polynomials();
    for (auto &poly : key_polys) {
      if (poly.representation() != ::bfv::math::rq::Representation::Ntt) {
        poly.change_representation(::bfv::math::rq::Representation::Ntt);
      }
      poly.disallow_variable_time_computations();
    }
    auto pk_ct = Ciphertext::from_polynomials_with_level(std::move(key_polys),
                                                         params, c.level());

    // Create implementation
    auto impl = std::make_unique<Impl>(params, std::move(pk_ct));

    return PublicKey(std::move(impl));

  } catch (const std::exception &e) {
    throw MathException("Failed to generate public key: " +
                        std::string(e.what()));
  }
}

Ciphertext PublicKey::encrypt(const Plaintext &plaintext,
                              std::mt19937_64 &rng) const {
  if (!pImpl) {
    throw ParameterException("Public key is not initialized");
  }

  if (plaintext.parameters() != parameters()) {
    throw ParameterException("Incompatible BFV parameters");
  }

  try {
    // Reuse stored public key directly when levels match; only clone when a
    // level switch is required.
    const Ciphertext *ct_ref = &pImpl->c;
    Ciphertext ct_level_adjusted;
    if (pImpl->c.level() != plaintext.level()) {
      ct_level_adjusted = pImpl->c;
      while (ct_level_adjusted.level() != plaintext.level()) {
        ct_level_adjusted.mod_switch_to_next_level();
      }
      ct_ref = &ct_level_adjusted;
    }

    const auto &ct_polys = ct_ref->polynomials();
    if (ct_polys.size() != 2) {
      throw MathException(
          "Public key ciphertext must have exactly 2 polynomials");
    }

    // Use the context at the target (plaintext) level
    auto ctx = pImpl->par->ctx_at_level(ct_ref->level());

    PROFILE_START("PK: Sample u, e1, e2");
    auto u_coeffs = SampleTernaryCoefficients(ctx->degree(), rng);
    auto e1 = ::bfv::math::rq::Poly::small(
        ctx, ::bfv::math::rq::Representation::PowerBasis,
        pImpl->par->variance(), rng);
    auto e2 = ::bfv::math::rq::Poly::small(
        ctx, ::bfv::math::rq::Representation::PowerBasis,
        pImpl->par->variance(), rng);

    // Enable variable-time for sampled polys as they are random/public
    e1.allow_variable_time_computations();
    e2.allow_variable_time_computations();

    // Plaintext contribution is also added in the coefficient domain.
    auto m = plaintext.polynomial_for_ops();
    m.allow_variable_time_computations();
    PROFILE_STOP("PK: Sample u, e1, e2");

    PROFILE_START("PK: Math c0 c1");
    auto c0 = ::bfv::math::rq::Poly::uninitialized(
        ctx, ::bfv::math::rq::Representation::PowerBasis);
    auto c1 = ::bfv::math::rq::Poly::uninitialized(
        ctx, ::bfv::math::rq::Representation::PowerBasis);
    c0.allow_variable_time_computations();
    c1.allow_variable_time_computations();

    const auto &moduli = ctx->q();
    const auto &ops = ctx->ops();
    const size_t degree = ctx->degree();
    std::vector<uint64_t> u_ntt(degree);
    for (size_t mod_idx = 0; mod_idx < moduli.size(); ++mod_idx) {
      const auto &qi = moduli[mod_idx];
      for (size_t k = 0; k < degree; ++k) {
        const int64_t sample = u_coeffs[k];
        u_ntt[k] = sample < 0 ? qi.P() - 1 : static_cast<uint64_t>(sample);
      }
      ops[mod_idx].ForwardInPlace(u_ntt.data());
      qi.MulToVt(c0.data(mod_idx), u_ntt.data(), ct_polys[0].data(mod_idx),
                 degree);
      qi.MulToVt(c1.data(mod_idx), u_ntt.data(), ct_polys[1].data(mod_idx),
                 degree);
      ops[mod_idx].BackwardInPlace(c0.data(mod_idx));
      ops[mod_idx].BackwardInPlace(c1.data(mod_idx));
    }
    c0 += e1;
    c0 += m;
    c1 += e2;
    PROFILE_STOP("PK: Math c0 c1");

    std::vector<::bfv::math::rq::Poly> result_polys;
    result_polys.reserve(2);
    result_polys.push_back(std::move(c0));
    result_polys.push_back(std::move(c1));

    // Create ciphertext with the correct level
    auto result = Ciphertext::from_polynomials_with_level(
        std::move(result_polys), pImpl->par, ct_ref->level());

    return result;

  } catch (const std::exception &e) {
    throw MathException("Failed to encrypt: " + std::string(e.what()));
  }
}

// Accessors
std::shared_ptr<BfvParameters> PublicKey::parameters() const {
  return pImpl ? pImpl->par : nullptr;
}

bool PublicKey::empty() const {
  return !pImpl || !pImpl->par || pImpl->c.empty();
}

const Ciphertext &PublicKey::ciphertext() const {
  if (!pImpl) {
    throw ParameterException("Public key is not initialized");
  }
  return pImpl->c;
}

// Equality operators
bool PublicKey::operator==(const PublicKey &other) const {
  if (!pImpl && !other.pImpl) return true;
  if (!pImpl || !other.pImpl) return false;

  const bool params_equal =
      (!pImpl->par && !other.pImpl->par) ||
      (pImpl->par && other.pImpl->par && *pImpl->par == *other.pImpl->par);
  return params_equal && pImpl->c == other.pImpl->c;
}

bool PublicKey::operator!=(const PublicKey &other) const {
  return !(*this == other);
}

// Serialization implementation
yacl::Buffer PublicKey::Serialize() const {
  if (!pImpl || !pImpl->par || pImpl->c.empty()) {
    throw SerializationException("PublicKey is not initialized");
  }

  auto serialized_ct = pImpl->c.Serialize();
  PublicKeyData data;
  data.ciphertext.assign(serialized_ct.data<uint8_t>(),
                         serialized_ct.data<uint8_t>() + serialized_ct.size());
  return MsgpackSerializer::Serialize(data);
}

void PublicKey::Deserialize(yacl::ByteContainerView in,
                            std::shared_ptr<BfvParameters> params) {
  *this = from_bytes(in, std::move(params));
}

PublicKey PublicKey::from_bytes(yacl::ByteContainerView bytes,
                                std::shared_ptr<BfvParameters> params) {
  if (!params) {
    throw SerializationException("Parameters are required for PublicKey");
  }

  try {
    auto data = MsgpackSerializer::Deserialize<PublicKeyData>(bytes);
    auto ciphertext = Ciphertext::from_bytes(
        yacl::ByteContainerView(data.ciphertext.data(), data.ciphertext.size()),
        params);
    return PublicKey::from_ciphertext(std::move(ciphertext), std::move(params));
  } catch (const SerializationException &) {
    throw;
  } catch (const std::exception &e) {
    throw SerializationException("Failed to deserialize PublicKey: " +
                                 std::string(e.what()));
  }
}

PublicKey PublicKey::from_ciphertext(Ciphertext ciphertext,
                                     std::shared_ptr<BfvParameters> params) {
  auto impl = std::make_unique<Impl>(params, std::move(ciphertext));
  return PublicKey(std::move(impl));
}

}  // namespace bfv
}  // namespace crypto
