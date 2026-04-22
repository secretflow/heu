#pragma once

#include "crypto/relinearization_key.h"
#include "crypto/rng_bridge.h"
#include "crypto/secret_key.h"

namespace crypto {
namespace bfv {

// Template implementations for RelinearizationKey

template <typename RNG>
RelinearizationKey RelinearizationKey::from_secret_key(
    const SecretKey &secret_key, RNG &rng) {
  return detail::WithMt19937_64(rng, [&](std::mt19937_64 &std_rng) {
    return from_secret_key(secret_key, std_rng);
  });
}

template <typename RNG>
RelinearizationKey RelinearizationKey::from_secret_key_leveled(
    const SecretKey &secret_key, size_t ciphertext_level, size_t key_level,
    RNG &rng) {
  return detail::WithMt19937_64(rng, [&](std::mt19937_64 &std_rng) {
    return from_secret_key_leveled(secret_key, ciphertext_level, key_level,
                                   std_rng);
  });
}

}  // namespace bfv
}  // namespace crypto
