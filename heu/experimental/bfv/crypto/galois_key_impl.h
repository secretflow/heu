#pragma once

#include "crypto/galois_key.h"
#include "crypto/rng_bridge.h"
#include "crypto/secret_key.h"

namespace crypto {
namespace bfv {

// Template implementations for GaloisKey

template <typename RNG>
GaloisKey GaloisKey::create(const SecretKey &secret_key, size_t exponent,
                            size_t ciphertext_level, size_t galois_key_level,
                            RNG &rng) {
  return detail::WithMt19937_64(rng, [&](std::mt19937_64 &std_rng) {
    return create(secret_key, exponent, ciphertext_level, galois_key_level,
                  std_rng);
  });
}

}  // namespace bfv
}  // namespace crypto
