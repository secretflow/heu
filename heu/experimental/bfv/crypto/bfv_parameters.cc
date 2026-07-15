#include "crypto/bfv_parameters.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <unordered_map>

#include "math/basis_mapper.h"
#include "math/biguint.h"
#include "math/context.h"
#include "math/modulus.h"
#include "math/ntt.h"
#include "math/poly.h"
#include "math/primes.h"
#include "math/representation.h"
#include "math/residue_transfer_engine.h"
#include "math/rns_context.h"
#include "math/scaling_factor.h"

// Serialization includes
#include "crypto/serialization/msgpack_adaptors.h"

// Encryption components for SelfTest
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/plaintext.h"
#include "crypto/secret_key.h"

namespace crypto {
namespace bfv {

namespace {
#if defined(HEU_BFV_MUL_USE_AUX_BASE) && HEU_BFV_MUL_USE_AUX_BASE
constexpr ::bfv::math::rns::RnsScalingScheme kCompiledMulRnsScheme =
    ::bfv::math::rns::RnsScalingScheme::AuxBase;
constexpr const char *kCompiledMulRnsSchemeName = "AUX_BASE";
#else
constexpr ::bfv::math::rns::RnsScalingScheme kCompiledMulRnsScheme =
    ::bfv::math::rns::RnsScalingScheme::ResidueTransfer;
constexpr const char *kCompiledMulRnsSchemeName = "RESIDUE_TRANSFER";
#endif
}  // namespace

// Forward declaration for internal multiplication context maps.
struct MulContextMaps {
  std::shared_ptr<::bfv::math::rq::BasisMapper> lift_mapper;
  std::shared_ptr<::bfv::math::rq::BasisMapper> reduce_mapper;
  std::shared_ptr<::bfv::math::rq::Context> source_ctx;
  std::shared_ptr<::bfv::math::rq::Context> extended_ctx;

  MulContextMaps(std::shared_ptr<::bfv::math::rq::BasisMapper> lift,
                 std::shared_ptr<::bfv::math::rq::BasisMapper> reduce,
                 std::shared_ptr<::bfv::math::rq::Context> source,
                 std::shared_ptr<::bfv::math::rq::Context> extended)
      : lift_mapper(std::move(lift)),
        reduce_mapper(std::move(reduce)),
        source_ctx(std::move(source)),
        extended_ctx(std::move(extended)) {}
};

// BfvParameters::Impl - PIMPL implementation
class BfvParameters::Impl {
 public:
  // Core parameters
  size_t polynomial_degree;
  uint64_t plaintext_modulus;
  std::vector<uint64_t> moduli;
  std::vector<size_t> moduli_sizes;
  size_t variance;

  // Computed values - using shared_ptr for copyability
  std::vector<std::shared_ptr<::bfv::math::rq::Context>> ctx;
  std::shared_ptr<::bfv::math::ntt::NttOperator> op;
  std::vector<::bfv::math::rq::Poly> delta;
  std::vector<uint64_t> q_mod_t;
  std::vector<std::shared_ptr<::bfv::math::rq::BasisMapper>> plaintext_mappers;
  std::shared_ptr<::bfv::math::zq::Modulus> plaintext_mod;
  std::vector<std::shared_ptr<MulContextMaps>> mul_level_maps;
  std::vector<size_t> matrix_reps_index_map;
  ::bfv::math::rns::RnsScalingScheme mul_rns_scaling_scheme;

  Impl()
      : polynomial_degree(0),
        plaintext_modulus(0),
        variance(10),
        mul_rns_scaling_scheme(kCompiledMulRnsScheme) {}
};

// BfvParametersBuilder::Impl - PIMPL implementation
class BfvParametersBuilder::Impl {
 public:
  size_t degree;
  uint64_t plaintext;
  size_t variance;
  std::vector<uint64_t> ciphertext_moduli;
  std::vector<size_t> ciphertext_moduli_sizes;
  ::bfv::math::rns::RnsScalingScheme mul_rns_scaling_scheme;

  Impl()
      : degree(0),
        plaintext(0),
        variance(10),
        mul_rns_scaling_scheme(kCompiledMulRnsScheme) {}
};

// BfvParameters implementation
BfvParameters::BfvParameters() : pImpl(std::make_unique<Impl>()) {}

BfvParameters::~BfvParameters() = default;

BfvParameters::BfvParameters(const BfvParameters &other)
    : pImpl(std::make_unique<Impl>(*other.pImpl)) {}

BfvParameters &BfvParameters::operator=(const BfvParameters &other) {
  if (this != &other) {
    *pImpl = *other.pImpl;
  }
  return *this;
}

BfvParameters::BfvParameters(BfvParameters &&other) noexcept = default;
BfvParameters &BfvParameters::operator=(BfvParameters &&other) noexcept =
    default;

BfvParameters::BfvParameters(std::unique_ptr<Impl> impl)
    : pImpl(std::move(impl)) {}

bool BfvParameters::operator==(const BfvParameters &other) const {
  return pImpl->polynomial_degree == other.pImpl->polynomial_degree &&
         pImpl->plaintext_modulus == other.pImpl->plaintext_modulus &&
         pImpl->moduli == other.pImpl->moduli &&
         pImpl->variance == other.pImpl->variance &&
         pImpl->mul_rns_scaling_scheme == other.pImpl->mul_rns_scaling_scheme;
}

bool BfvParameters::operator!=(const BfvParameters &other) const {
  return !(*this == other);
}

size_t BfvParameters::degree() const { return pImpl->polynomial_degree; }

uint64_t BfvParameters::plaintext_modulus() const {
  return pImpl->plaintext_modulus;
}

const std::vector<uint64_t> &BfvParameters::moduli() const {
  return pImpl->moduli;
}

const std::vector<size_t> &BfvParameters::moduli_sizes() const {
  return pImpl->moduli_sizes;
}

size_t BfvParameters::max_level() const { return pImpl->moduli.size() - 1; }

size_t BfvParameters::variance() const { return pImpl->variance; }

::bfv::math::rns::RnsScalingScheme BfvParameters::mul_rns_scaling_scheme()
    const {
  return kCompiledMulRnsScheme;
}

std::shared_ptr<::bfv::math::rq::Context> BfvParameters::ctx_at_level(
    size_t level) const {
  if (level >= pImpl->ctx.size()) {
    throw ParameterException("Invalid level: " + std::to_string(level));
  }
  return pImpl->ctx[level];
}

size_t BfvParameters::level_of_ctx(
    const std::shared_ptr<::bfv::math::rq::Context> &ctx) const {
  return pImpl->ctx[0]->niterations_to(ctx);
}

std::shared_ptr<::bfv::math::rq::BasisMapper>
BfvParameters::plaintext_mapper_at_level(size_t level) const {
  if (level >= pImpl->plaintext_mappers.size()) {
    throw ParameterException("Invalid level: " + std::to_string(level));
  }
  return pImpl->plaintext_mappers[level];
}

const ::bfv::math::rq::Poly &BfvParameters::delta_at_level(size_t level) const {
  if (level >= pImpl->delta.size()) {
    throw ParameterException("Invalid level: " + std::to_string(level));
  }
  return pImpl->delta[level];
}

uint64_t BfvParameters::q_mod_t_at_level(size_t level) const {
  if (level >= pImpl->q_mod_t.size()) {
    throw ParameterException("Invalid level: " + std::to_string(level));
  }
  return pImpl->q_mod_t[level];
}

const std::vector<size_t> &BfvParameters::matrix_reps_index_map() const {
  return pImpl->matrix_reps_index_map;
}

std::shared_ptr<::bfv::math::ntt::NttOperator> BfvParameters::ntt_operator()
    const {
  return pImpl->op;
}

std::vector<uint64_t> BfvParameters::plaintext_random_vec(
    size_t size, std::mt19937_64 &rng) const {
  if (!pImpl->plaintext_mod) {
    throw ParameterException("Plaintext modulus not initialized");
  }
  return pImpl->plaintext_mod->RandomVec(size, rng);
}

std::vector<std::shared_ptr<BfvParameters>>
BfvParameters::default_parameters_128(size_t plaintext_nbits) {
  if (plaintext_nbits >= 64) {
    throw ParameterException("plaintext_nbits must be < 64");
  }

  std::unordered_map<size_t, std::vector<uint64_t>> n_and_qs;
  n_and_qs[1024] = {0x7e00001};
  n_and_qs[2048] = {0x3fffffff000001};
  n_and_qs[4096] = {0xffffee001, 0xffffc4001, 0x1ffffe0001};
  n_and_qs[8192] = {0x7fffffd8001, 0x7fffffc8001, 0xfffffffc001, 0xffffff6c001,
                    0xfffffebc001};
  n_and_qs[16384] = {0xfffffffd8001,  0xfffffffa0001,  0xfffffff00001,
                     0x1fffffff68001, 0x1fffffff50001, 0x1ffffffee8001,
                     0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001};

  std::vector<std::shared_ptr<BfvParameters>> params;

  // Sort keys for consistent ordering
  std::vector<size_t> degrees;
  for (const auto &pair : n_and_qs) {
    degrees.push_back(pair.first);
  }
  std::sort(degrees.begin(), degrees.end());

  for (size_t n : degrees) {
    const auto &moduli = n_and_qs[n];

    // Generate plaintext modulus using proper prime generation
    uint64_t upper_bound = (1ULL << plaintext_nbits) - 1;
    auto plaintext_opt =
        ::bfv::math::zq::generate_prime(plaintext_nbits, 2 * n, upper_bound);
    if (!plaintext_opt) {
      continue;  // Skip this parameter set if we can't generate a suitable
                 // prime
    }
    uint64_t plaintext_modulus = *plaintext_opt;

    try {
      auto param = BfvParametersBuilder()
                       .set_degree(n)
                       .set_plaintext_modulus(plaintext_modulus)
                       .set_moduli(moduli)
                       .build_arc();
      params.push_back(param);
    } catch (const BfvException &) {
      // Skip this parameter set if it fails
      continue;
    }
  }

  return params;
}

bool BfvParameters::SelfTest(std::string *detailed_report) const {
  std::stringstream ss;
  bool success = true;

  try {
    ss << "Starting SelfTest for BFV Parameters:\n";
    ss << "  Degree: " << degree() << "\n";
    ss << "  Plaintext Modulus: " << plaintext_modulus() << "\n";
    ss << "  Moduli count: " << moduli().size() << "\n";

    // Create copy of parameters for shared_ptr
    auto params_ptr = std::make_shared<BfvParameters>(*this);

    // Create keys
    // Create keys
    std::mt19937_64 key_rng(42);
    SecretKey secret_key(SecretKey::random(params_ptr, key_rng));

    // Test Case 1: Constant
    {
      ss << "  Test 1: Encrypt/Decrypt Zero... ";
      // Uses polynomial encoding (coefficients)
      Plaintext pt = Plaintext::zero(Encoding::poly(), params_ptr);

      // Encrypt
      std::mt19937_64 rng(12345);
      Ciphertext ct = secret_key.encrypt(pt, rng);

      // Decrypt
      Plaintext pt_dec = secret_key.decrypt(ct);

      if (pt_dec != pt) {
        ss << "FAILED (mismatch)\n";
        success = false;
      } else {
        ss << "OK\n";
      }
    }

    // Test Case 2: Random Vector
    {
      ss << "  Test 2: Encrypt/Decrypt Random Vec... ";
      std::mt19937_64 rng(5678);
      std::vector<uint64_t> vec = plaintext_random_vec(degree(), rng);
      Plaintext pt = Plaintext::encode(vec, Encoding::poly(), params_ptr);

      Ciphertext ct = secret_key.encrypt(pt, rng);
      Plaintext pt_dec = secret_key.decrypt(ct);

      if (pt_dec != pt) {
        ss << "FAILED (mismatch)\n";
        success = false;
      } else {
        ss << "OK\n";
      }
    }

  } catch (const std::exception &e) {
    ss << "  FAILED with exception: " << e.what() << "\n";
    success = false;
  }

  if (detailed_report) {
    *detailed_report = ss.str();
  }
  return success;
}

std::shared_ptr<BfvParameters> BfvParameters::default_arc(size_t num_moduli,
                                                          size_t degree) {
  if (!((degree & (degree - 1)) == 0) || degree < 8) {
    throw ParameterException("Invalid degree: must be power of 2 and >= 8");
  }

  std::vector<size_t> moduli_sizes(num_moduli, 62);
  return BfvParametersBuilder()
      .set_degree(degree)
      .set_plaintext_modulus(1153)
      .set_moduli_sizes(moduli_sizes)
      .set_variance(10)
      .build_arc();
}

yacl::Buffer BfvParameters::Serialize() const {
  BfvParametersData data;
  data.polynomial_degree = pImpl->polynomial_degree;
  data.plaintext_modulus = pImpl->plaintext_modulus;
  data.moduli = pImpl->moduli;
  data.moduli_sizes = pImpl->moduli_sizes;
  data.variance = pImpl->variance;
  return MsgpackSerializer::Serialize(data);
}

void BfvParameters::Deserialize(yacl::ByteContainerView in) {
  try {
    auto data = MsgpackSerializer::Deserialize<BfvParametersData>(in);

    // Use builder to properly reconstruct parameters with computed values
    auto params = BfvParametersBuilder()
                      .set_degree(data.polynomial_degree)
                      .set_plaintext_modulus(data.plaintext_modulus)
                      .set_moduli(data.moduli)
                      .set_variance(data.variance)
                      .build();

    // Copy the reconstructed impl
    *pImpl = *params.pImpl;
  } catch (const std::exception &e) {
    throw SerializationException("Failed to deserialize BfvParameters: " +
                                 std::string(e.what()));
  }
}

std::shared_ptr<BfvParameters> BfvParameters::from_bytes(
    yacl::ByteContainerView bytes) {
  try {
    auto data = MsgpackSerializer::Deserialize<BfvParametersData>(bytes);

    // Use builder to properly reconstruct parameters with computed values
    return BfvParametersBuilder()
        .set_degree(data.polynomial_degree)
        .set_plaintext_modulus(data.plaintext_modulus)
        .set_moduli(data.moduli)
        .set_variance(data.variance)
        .build_arc();
  } catch (const std::exception &e) {
    throw SerializationException("Failed to deserialize BfvParameters: " +
                                 std::string(e.what()));
  }
}

// BfvParametersBuilder implementation
BfvParametersBuilder::BfvParametersBuilder()
    : pImpl(std::make_unique<Impl>()) {}

BfvParametersBuilder::~BfvParametersBuilder() = default;

BfvParametersBuilder::BfvParametersBuilder(const BfvParametersBuilder &other)
    : pImpl(std::make_unique<Impl>(*other.pImpl)) {}

BfvParametersBuilder &BfvParametersBuilder::operator=(
    const BfvParametersBuilder &other) {
  if (this != &other) {
    *pImpl = *other.pImpl;
  }
  return *this;
}

BfvParametersBuilder::BfvParametersBuilder(
    BfvParametersBuilder &&other) noexcept = default;
BfvParametersBuilder &BfvParametersBuilder::operator=(
    BfvParametersBuilder &&other) noexcept = default;

BfvParametersBuilder &BfvParametersBuilder::set_degree(size_t degree) {
  pImpl->degree = degree;
  return *this;
}

BfvParametersBuilder &BfvParametersBuilder::set_plaintext_modulus(
    uint64_t plaintext) {
  pImpl->plaintext = plaintext;
  return *this;
}

BfvParametersBuilder &BfvParametersBuilder::set_moduli_sizes(
    const std::vector<size_t> &sizes) {
  pImpl->ciphertext_moduli_sizes = sizes;
  return *this;
}

BfvParametersBuilder &BfvParametersBuilder::set_moduli(
    const std::vector<uint64_t> &moduli) {
  pImpl->ciphertext_moduli = moduli;
  return *this;
}

BfvParametersBuilder &BfvParametersBuilder::set_variance(size_t variance) {
  pImpl->variance = variance;
  return *this;
}

BfvParametersBuilder &BfvParametersBuilder::set_mul_rns_scaling_scheme(
    ::bfv::math::rns::RnsScalingScheme scheme) {
  if (scheme != kCompiledMulRnsScheme) {
    throw ParameterException(
        std::string("RNS multiplication scheme is fixed at compile time to ") +
        kCompiledMulRnsSchemeName);
  }
  pImpl->mul_rns_scaling_scheme = kCompiledMulRnsScheme;
  return *this;
}

std::vector<uint64_t> BfvParametersBuilder::generate_moduli(
    const std::vector<size_t> &moduli_sizes, size_t degree) {
  auto select_ntt_friendly_primes = [&](size_t bit_size,
                                        size_t count) -> std::vector<uint64_t> {
    if (bit_size > 62 || bit_size < 10) {
      throw ParameterException(
          "Invalid modulus size: " + std::to_string(bit_size) +
          " (must be between 10 and 62)");
    }
    if (count == 0) {
      return {};
    }

    std::vector<uint64_t> primes;
    primes.reserve(count);
    const uint64_t step = 2ULL * degree;
    uint64_t value = (1ULL << bit_size) - step + 1;
    const uint64_t lower_bound = 1ULL << (bit_size - 1);

    while (count > 0 && value > lower_bound) {
      if (::bfv::math::zq::is_prime(value)) {
        primes.push_back(value);
        --count;
      }
      if (value <= step) {
        break;
      }
      value -= step;
    }

    if (count > 0) {
      throw ParameterException("Not enough primes of size " +
                               std::to_string(bit_size) + " for degree " +
                               std::to_string(degree));
    }
    return primes;
  };

  std::unordered_map<size_t, size_t> count_table;
  std::unordered_map<size_t, std::vector<uint64_t>> prime_table;
  for (size_t size : moduli_sizes) {
    ++count_table[size];
  }
  for (const auto &entry : count_table) {
    prime_table[entry.first] =
        select_ntt_friendly_primes(entry.first, entry.second);
  }

  std::vector<uint64_t> moduli;
  moduli.reserve(moduli_sizes.size());
  for (size_t size : moduli_sizes) {
    auto &primes = prime_table[size];
    if (primes.empty()) {
      throw ParameterException("Prime table underflow for modulus size " +
                               std::to_string(size));
    }
    moduli.push_back(primes.front());
    primes.erase(primes.begin());
  }

  return moduli;
}

std::shared_ptr<BfvParameters> BfvParametersBuilder::build_arc() {
  auto built = build();
  return std::make_shared<BfvParameters>(std::move(built));
}

BfvParameters BfvParametersBuilder::build() {
  // Validate polynomial degree constraints.
  if (pImpl->degree < 8 || !((pImpl->degree & (pImpl->degree - 1)) == 0)) {
    throw ParameterException("Invalid degree: " +
                             std::to_string(pImpl->degree));
  }

  // Validate plaintext modulus.
  auto plaintext_modulus = ::bfv::math::zq::Modulus::New(pImpl->plaintext);
  if (!plaintext_modulus) {
    throw ParameterException("Invalid plaintext modulus: " +
                             std::to_string(pImpl->plaintext));
  }

  // Exactly one of explicit moduli or modulus bit-sizes must be provided.
  if (!pImpl->ciphertext_moduli.empty() &&
      !pImpl->ciphertext_moduli_sizes.empty()) {
    throw ParameterException(
        "Only one of `ciphertext_moduli` and `ciphertext_moduli_sizes` can be "
        "specified");
  } else if (pImpl->ciphertext_moduli.empty() &&
             pImpl->ciphertext_moduli_sizes.empty()) {
    throw ParameterException(
        "One of `ciphertext_moduli` and `ciphertext_moduli_sizes` must be "
        "specified");
  }

  // Resolve ciphertext modulus chain.
  std::vector<uint64_t> moduli = pImpl->ciphertext_moduli;
  if (!pImpl->ciphertext_moduli_sizes.empty()) {
    moduli = generate_moduli(pImpl->ciphertext_moduli_sizes, pImpl->degree);
  }

  // Recompute the moduli sizes
  std::vector<size_t> moduli_sizes;
  for (uint64_t m : moduli) {
    moduli_sizes.push_back(64 - __builtin_clzll(m));
  }

  constexpr size_t kInternalAuxModBitCount = 61;
  size_t plain_modulus_bit_count = 0;
  {
    uint64_t plain = pImpl->plaintext;
    while (plain > 0) {
      ++plain_modulus_bit_count;
      plain >>= 1;
    }
    if (plain_modulus_bit_count == 0) {
      plain_modulus_bit_count = 1;
    }
  }
  auto compute_base_bsk_size = [&](size_t coeff_bit_count,
                                   size_t q_size) -> size_t {
    size_t base_B_size = q_size;
    if (32 + plain_modulus_bit_count + coeff_bit_count >=
        kInternalAuxModBitCount * q_size + kInternalAuxModBitCount) {
      ++base_B_size;
    }
    return base_B_size + 1;
  };

  size_t max_extended_basis_size = 0;
  for (size_t level = 0; level < moduli.size(); ++level) {
    const size_t q_size = moduli.size() - level;
    size_t coeff_bit_count = 0;
    for (size_t j = 0; j < q_size; ++j) {
      coeff_bit_count += moduli_sizes[j];
    }
    max_extended_basis_size =
        std::max(max_extended_basis_size,
                 compute_base_bsk_size(coeff_bit_count, q_size));
  }

  // Build an auxiliary basis for multiplication routines.
  std::vector<uint64_t> extended_basis;
  extended_basis.reserve(max_extended_basis_size);
  uint64_t upper_bound = 1ULL << kInternalAuxModBitCount;
  while (extended_basis.size() < max_extended_basis_size) {
    auto prime_opt = ::bfv::math::zq::generate_prime(
        kInternalAuxModBitCount, 2 * pImpl->degree, upper_bound);
    if (prime_opt) {
      uint64_t prime = *prime_opt;
      if (std::find(extended_basis.begin(), extended_basis.end(), prime) ==
              extended_basis.end() &&
          std::find(moduli.begin(), moduli.end(), prime) == moduli.end()) {
        extended_basis.push_back(prime);
      }
      upper_bound = prime;
    } else {
      throw ParameterException("Failed to generate extended basis moduli");
    }
  }

  // Create NTT operator
  auto op =
      ::bfv::math::ntt::NttOperator::New(*plaintext_modulus, pImpl->degree);

  // Create plaintext context
  std::vector<uint64_t> plaintext_moduli = {pImpl->plaintext};
  auto plaintext_ctx =
      ::bfv::math::rq::Context::create_arc(plaintext_moduli, pImpl->degree);

  // Compute delta_rests
  std::vector<uint64_t> delta_rests;
  for (uint64_t m : moduli) {
    auto q = ::bfv::math::zq::Modulus::New(m);
    if (!q) {
      throw ParameterException("Invalid modulus: " + std::to_string(m));
    }
    // delta_rest = q.inv(q.neg(plaintext_modulus))
    uint64_t neg_t = q->Sub(0, pImpl->plaintext);
    auto inv_opt = q->Inv(neg_t);
    if (!inv_opt) {
      throw ParameterException("Failed to compute modular inverse");
    }
    delta_rests.push_back(*inv_opt);
  }

  // Create implementation
  auto impl = std::make_unique<BfvParameters::Impl>();
  impl->polynomial_degree = pImpl->degree;
  impl->plaintext_modulus = pImpl->plaintext;
  impl->moduli = moduli;
  impl->moduli_sizes = moduli_sizes;
  impl->variance = pImpl->variance;
  impl->mul_rns_scaling_scheme = kCompiledMulRnsScheme;
  impl->plaintext_mod =
      std::make_shared<::bfv::math::zq::Modulus>(std::move(*plaintext_modulus));
  if (op) {
    impl->op = std::make_shared<::bfv::math::ntt::NttOperator>(std::move(*op));
  }

  // Initialize contexts, delta, q_mod_t, plaintext mappers, and multiply
  // context maps for each level
  impl->ctx.reserve(moduli.size());
  impl->delta.reserve(moduli.size());
  impl->q_mod_t.reserve(moduli.size());
  impl->plaintext_mappers.reserve(moduli.size());
  impl->mul_level_maps.reserve(moduli.size());

  for (size_t i = 0; i < moduli.size(); ++i) {
    // Create RNS context for level i
    std::vector<uint64_t> level_moduli(moduli.begin(), moduli.end() - i);
    auto rns = ::bfv::math::rns::RnsContext::create(level_moduli);

    // Create context for level i
    auto ctx_i =
        ::bfv::math::rq::Context::create_arc(level_moduli, pImpl->degree);
    impl->ctx.push_back(ctx_i);

    // Create delta polynomial
    std::vector<uint64_t> delta_rest_slice(delta_rests.begin(),
                                           delta_rests.end() - i);

    auto lifted = rns->lift(delta_rest_slice);

    std::vector<::bfv::math::rns::BigUint> delta_coeffs(
        pImpl->degree, ::bfv::math::rns::BigUint(0));
    delta_coeffs[0] = lifted;  // Set the constant term

    auto delta_poly = ::bfv::math::rq::Poly::from_biguint_vector(
        delta_coeffs, ctx_i, true, ::bfv::math::rq::Representation::PowerBasis);
    delta_poly.change_representation(::bfv::math::rq::Representation::NttShoup);
    impl->delta.push_back(std::move(delta_poly));

    // Compute q_mod_t
    auto q_mod_t_val =
        rns->modulus() % ::bfv::math::rns::BigUint(pImpl->plaintext);
    impl->q_mod_t.push_back(q_mod_t_val.to_u64());

    // Create basis mapper
    auto scaling_factor = ::bfv::math::rns::ScalingFactor(
        ::bfv::math::rns::BigUint(pImpl->plaintext), rns->modulus());
    auto mapper = ::bfv::math::rq::BasisMapper::create(ctx_i, plaintext_ctx,
                                                       scaling_factor);
    impl->plaintext_mappers.push_back(
        std::shared_ptr<::bfv::math::rq::BasisMapper>(mapper.release()));

    // Create multiplication parameters
    size_t coeff_bit_count = 0;
    for (size_t j = 0; j < moduli_sizes.size() - i; ++j) {
      coeff_bit_count += moduli_sizes[j];
    }
    const size_t base_bsk_size =
        compute_base_bsk_size(coeff_bit_count, level_moduli.size());
    size_t n_moduli = std::min(base_bsk_size, extended_basis.size());

    std::vector<uint64_t> mul_1_moduli = level_moduli;
    for (size_t j = 0; j < std::min(n_moduli, extended_basis.size()); ++j) {
      mul_1_moduli.push_back(extended_basis[j]);
    }
    auto mul_1_ctx =
        ::bfv::math::rq::Context::create_arc(mul_1_moduli, pImpl->degree);

    auto mul_lift_mapper = ::bfv::math::rq::BasisMapper::create(
        ctx_i, mul_1_ctx, ::bfv::math::rns::ScalingFactor::one());
    auto post_mul_mapper = ::bfv::math::rq::BasisMapper::create(
        mul_1_ctx, ctx_i,
        ::bfv::math::rns::ScalingFactor(
            ::bfv::math::rns::BigUint(pImpl->plaintext), ctx_i->modulus()));

    auto mul_maps = std::make_shared<MulContextMaps>(
        std::shared_ptr<::bfv::math::rq::BasisMapper>(
            mul_lift_mapper.release()),
        std::shared_ptr<::bfv::math::rq::BasisMapper>(
            post_mul_mapper.release()),
        ctx_i, mul_1_ctx);
    impl->mul_level_maps.push_back(mul_maps);
  }

  // We use the same code as standard implementations for matrix_reps_index_map
  size_t row_size = pImpl->degree >> 1;
  size_t m = pImpl->degree << 1;
  size_t gen = 3;
  size_t pos = 1;
  impl->matrix_reps_index_map.resize(pImpl->degree);

  // Platform-specific bit reversal function
#if defined(__GNUC__) &&                                        \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)) && \
    defined(__has_builtin)
#if __has_builtin(__builtin_bitreverse64)
#define HAS_BUILTIN_BITREVERSE64 1
#endif
#endif

#ifndef HAS_BUILTIN_BITREVERSE64
  // Fallback bit reversal implementation for compilers without
  // __builtin_bitreverse64
  auto bit_reverse_64 = [](uint64_t x) -> uint64_t {
    x = ((x & 0x5555555555555555ULL) << 1) | ((x & 0xAAAAAAAAAAAAAAAAULL) >> 1);
    x = ((x & 0x3333333333333333ULL) << 2) | ((x & 0xCCCCCCCCCCCCCCCCULL) >> 2);
    x = ((x & 0x0F0F0F0F0F0F0F0FULL) << 4) | ((x & 0xF0F0F0F0F0F0F0F0ULL) >> 4);
    x = ((x & 0x00FF00FF00FF00FFULL) << 8) | ((x & 0xFF00FF00FF00FF00ULL) >> 8);
    x = ((x & 0x0000FFFF0000FFFFULL) << 16) |
        ((x & 0xFFFF0000FFFF0000ULL) >> 16);
    x = ((x & 0x00000000FFFFFFFFULL) << 32) |
        ((x & 0xFFFFFFFF00000000ULL) >> 32);
    return x;
  };
#endif

  for (size_t i = 0; i < row_size; ++i) {
    size_t index1 = (pos - 1) >> 1;
    size_t index2 = (m - pos - 1) >> 1;

    // Reverse bits operation
    size_t leading_zeros = __builtin_clzll(pImpl->degree) + 1;
#ifdef HAS_BUILTIN_BITREVERSE64
    impl->matrix_reps_index_map[i] =
        __builtin_bitreverse64(index1) >> leading_zeros;
    impl->matrix_reps_index_map[row_size | i] =
        __builtin_bitreverse64(index2) >> leading_zeros;
#else
    impl->matrix_reps_index_map[i] = bit_reverse_64(index1) >> leading_zeros;
    impl->matrix_reps_index_map[row_size | i] =
        bit_reverse_64(index2) >> leading_zeros;
#endif

    pos *= gen;
    pos &= m - 1;
  }

  return BfvParameters(std::move(impl));
}

}  // namespace bfv
}  // namespace crypto
