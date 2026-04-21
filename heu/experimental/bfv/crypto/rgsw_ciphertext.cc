#include "crypto/rgsw_ciphertext.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <random>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/key_switching_key.h"
#include "crypto/plaintext.h"
#include "crypto/secret_key.h"
#include "math/context.h"
#include "math/modulus.h"
#include "math/poly.h"
#include "math/representation.h"

// Serialization includes
#include "crypto/serialization/msgpack_adaptors.h"

namespace crypto {
namespace bfv {

// RGSWCiphertext::Impl - PIMPL implementation
class RGSWCiphertext::Impl {
 public:
  KeySwitchingKey ksk0;  // Key switching key for m
  KeySwitchingKey ksk1;  // Key switching key for m*s

  // Constructor from key switching keys
  Impl(KeySwitchingKey ksk0_key, KeySwitchingKey ksk1_key)
      : ksk0(std::move(ksk0_key)), ksk1(std::move(ksk1_key)) {}
};

// RGSWCiphertext implementation
RGSWCiphertext::~RGSWCiphertext() = default;

RGSWCiphertext::RGSWCiphertext(const RGSWCiphertext &other)
    : pImpl(std::make_unique<Impl>(*other.pImpl)) {}

RGSWCiphertext &RGSWCiphertext::operator=(const RGSWCiphertext &other) {
  if (this != &other) {
    *pImpl = *other.pImpl;
  }
  return *this;
}

RGSWCiphertext::RGSWCiphertext(RGSWCiphertext &&other) noexcept = default;
RGSWCiphertext &RGSWCiphertext::operator=(RGSWCiphertext &&other) noexcept =
    default;

RGSWCiphertext::RGSWCiphertext(std::unique_ptr<Impl> impl)
    : pImpl(std::move(impl)) {}

RGSWCiphertext RGSWCiphertext::create_from_keys(KeySwitchingKey ksk0,
                                                KeySwitchingKey ksk1) {
  auto impl = std::make_unique<Impl>(std::move(ksk0), std::move(ksk1));
  return RGSWCiphertext(std::move(impl));
}

// Accessors
std::shared_ptr<BfvParameters> RGSWCiphertext::parameters() const {
  return pImpl ? pImpl->ksk0.parameters() : nullptr;
}

size_t RGSWCiphertext::level() const {
  return pImpl ? pImpl->ksk0.ciphertext_level() : 0;
}

bool RGSWCiphertext::empty() const {
  return !pImpl || pImpl->ksk0.empty() || pImpl->ksk1.empty();
}

// Equality operators
bool RGSWCiphertext::operator==(const RGSWCiphertext &other) const {
  if (!pImpl && !other.pImpl) return true;
  if (!pImpl || !other.pImpl) return false;

  return pImpl->ksk0 == other.pImpl->ksk0 && pImpl->ksk1 == other.pImpl->ksk1;
}

bool RGSWCiphertext::operator!=(const RGSWCiphertext &other) const {
  return !(*this == other);
}

// Arithmetic operations
RGSWCiphertext RGSWCiphertext::operator+(const RGSWCiphertext &other) const {
  if (!pImpl || !other.pImpl) {
    throw ParameterException("RGSW ciphertext is not initialized");
  }

  // Check parameter compatibility
  if (pImpl->ksk0.parameters() != other.pImpl->ksk0.parameters()) {
    throw ParameterException("RGSW ciphertexts have incompatible parameters");
  }

  // Add the key switching keys component-wise
  auto ksk0_sum = pImpl->ksk0 + other.pImpl->ksk0;
  auto ksk1_sum = pImpl->ksk1 + other.pImpl->ksk1;

  // Create new RGSW ciphertext from the sum
  return RGSWCiphertext::create_from_keys(std::move(ksk0_sum),
                                          std::move(ksk1_sum));
}

// Accessor methods for serialization
const KeySwitchingKey &RGSWCiphertext::ksk0() const {
  if (!pImpl) {
    throw ParameterException("RGSWCiphertext is not initialized");
  }
  return pImpl->ksk0;
}

const KeySwitchingKey &RGSWCiphertext::ksk1() const {
  if (!pImpl) {
    throw ParameterException("RGSWCiphertext is not initialized");
  }
  return pImpl->ksk1;
}

// Serialization implementation
yacl::Buffer RGSWCiphertext::Serialize() const {
  if (!pImpl || pImpl->ksk0.empty() || pImpl->ksk1.empty()) {
    throw SerializationException("RGSWCiphertext is not initialized");
  }

  auto serialized_ksk0 = pImpl->ksk0.Serialize();
  auto serialized_ksk1 = pImpl->ksk1.Serialize();
  RGSWCiphertextData data;
  data.ksk0.assign(serialized_ksk0.data<uint8_t>(),
                   serialized_ksk0.data<uint8_t>() + serialized_ksk0.size());
  data.ksk1.assign(serialized_ksk1.data<uint8_t>(),
                   serialized_ksk1.data<uint8_t>() + serialized_ksk1.size());
  return MsgpackSerializer::Serialize(data);
}

void RGSWCiphertext::Deserialize(yacl::ByteContainerView in,
                                 std::shared_ptr<BfvParameters> params) {
  *this = from_bytes(in, std::move(params));
}

RGSWCiphertext RGSWCiphertext::from_bytes(
    yacl::ByteContainerView bytes, std::shared_ptr<BfvParameters> params) {
  if (!params) {
    throw SerializationException("Parameters are required for RGSWCiphertext");
  }

  try {
    auto data = MsgpackSerializer::Deserialize<RGSWCiphertextData>(bytes);
    auto ksk0 = KeySwitchingKey::from_bytes(
        yacl::ByteContainerView(data.ksk0.data(), data.ksk0.size()), params);
    auto ksk1 = KeySwitchingKey::from_bytes(
        yacl::ByteContainerView(data.ksk1.data(), data.ksk1.size()), params);
    return create_from_keys(std::move(ksk0), std::move(ksk1));
  } catch (const SerializationException &) {
    throw;
  } catch (const std::exception &e) {
    throw SerializationException("Failed to deserialize RGSWCiphertext: " +
                                 std::string(e.what()));
  }
}

// External product operations
Ciphertext operator*(const Ciphertext &ct, const RGSWCiphertext &rgsw) {
  if (!rgsw.pImpl) {
    throw ParameterException("RGSW ciphertext is not initialized");
  }

  if (ct.parameters() != rgsw.parameters()) {
    throw ParameterException(
        "Ciphertext and RGSWCiphertext must have the same parameters");
  }

  if (ct.level() != rgsw.level()) {
    throw ParameterException(
        "Ciphertext and RGSWCiphertext must have the same level");
  }

  const auto &ct_polys = ct.polynomials();
  if (ct_polys.size() != 2) {
    throw ParameterException("Ciphertext must have two parts");
  }

  try {
    // Convert ciphertext polynomials to PowerBasis for key switching
    auto ct0 = ct_polys[0];
    auto ct1 = ct_polys[1];
    ct0.change_representation(::bfv::math::rq::Representation::PowerBasis);
    ct1.change_representation(::bfv::math::rq::Representation::PowerBasis);

    // Perform key switching operations
    auto [c0, c1] = rgsw.pImpl->ksk0.key_switch(ct0);
    auto [c0p, c1p] = rgsw.pImpl->ksk1.key_switch(ct1);

    // Add the results
    auto result_c0 = c0 + c0p;
    auto result_c1 = c1 + c1p;

    // Create result ciphertext
    std::vector<::bfv::math::rq::Poly> result_polys = {std::move(result_c0),
                                                       std::move(result_c1)};

    return Ciphertext::from_polynomials_with_level(result_polys,
                                                   ct.parameters(), ct.level());

  } catch (const std::exception &e) {
    throw MathException("Failed to compute external product: " +
                        std::string(e.what()));
  }
}

Ciphertext operator*(const RGSWCiphertext &rgsw, const Ciphertext &ct) {
  // External product is commutative
  return ct * rgsw;
}

}  // namespace bfv
}  // namespace crypto
