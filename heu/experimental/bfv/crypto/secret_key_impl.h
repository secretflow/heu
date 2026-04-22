#pragma once

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/plaintext.h"
#include "crypto/rng_bridge.h"
#include "crypto/secret_key.h"
#include "math/poly.h"
#include "math/sample_vec_cbd.h"

namespace crypto {
namespace bfv {

// Template method implementations

template <typename RNG>
SecretKey SecretKey::random(std::shared_ptr<BfvParameters> params, RNG &rng) {
  if (!params) {
    throw ParameterException("Parameters cannot be null");
  }

  // Generate coefficients using CBD sampling
  auto coeffs = ::bfv::math::utils::sample_vec_cbd(params->degree(),
                                                   params->variance(), rng);

  return SecretKey(coeffs, params);
}

template <typename RNG>
Ciphertext SecretKey::encrypt(const Plaintext &plaintext, RNG &rng) const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }

  if (plaintext.parameters() != parameters()) {
    throw ParameterException("Incompatible BFV parameters");
  }

  // Convert plaintext to polynomial and encrypt
  auto poly = plaintext.to_poly();
  return encrypt_poly(poly, rng);
}

template <typename RNG>
Ciphertext SecretKey::encrypt_poly(const ::bfv::math::rq::Poly &poly,
                                   RNG &rng) const {
  return detail::WithMt19937_64(rng, [&](std::mt19937_64 &std_rng) {
    return encrypt_poly_impl(poly, std_rng);
  });
}

}  // namespace bfv
}  // namespace crypto
