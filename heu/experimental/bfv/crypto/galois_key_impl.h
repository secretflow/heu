#pragma once

#include "crypto/galois_key.h"
#include "crypto/secret_key.h"

namespace crypto {
namespace bfv {

// Template implementations for GaloisKey

template <typename RNG>
GaloisKey GaloisKey::create(const SecretKey &secret_key, size_t exponent,
                            size_t ciphertext_level, size_t galois_key_level,
                            RNG &rng) {
  // Forward to the std::mt19937_64 implementation
  // This is a simple approach - in a full implementation, we might want
  // to handle different RNG types more generically
  std::mt19937_64 mt_rng;
  mt_rng.seed(rng());
  return create(secret_key, exponent, ciphertext_level, galois_key_level,
                mt_rng);
}

}  // namespace bfv
}  // namespace crypto
