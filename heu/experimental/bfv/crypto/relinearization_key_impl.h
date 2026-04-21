#pragma once

#include "crypto/relinearization_key.h"
#include "crypto/secret_key.h"

namespace crypto {
namespace bfv {

// Template implementations for RelinearizationKey

template <typename RNG>
RelinearizationKey RelinearizationKey::from_secret_key(
    const SecretKey &secret_key, RNG &rng) {
  // Forward to the implementation method
  return from_secret_key(secret_key, static_cast<std::mt19937_64 &>(rng));
}

template <typename RNG>
RelinearizationKey RelinearizationKey::from_secret_key_leveled(
    const SecretKey &secret_key, size_t ciphertext_level, size_t key_level,
    RNG &rng) {
  // Forward to the implementation method
  return from_secret_key_leveled(secret_key, ciphertext_level, key_level,
                                 static_cast<std::mt19937_64 &>(rng));
}

}  // namespace bfv
}  // namespace crypto
