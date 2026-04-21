#pragma once

#include "crypto/key_switching_key.h"
#include "crypto/secret_key.h"

namespace crypto {
namespace bfv {

// Template implementations for KeySwitchingKey

template <typename RNG>
KeySwitchingKey KeySwitchingKey::create(const SecretKey &secret_key,
                                        const ::bfv::math::rq::Poly &from,
                                        size_t ciphertext_level,
                                        size_t ksk_level, RNG &rng) {
  return create_with_std_rng_bridge(secret_key, from, ciphertext_level,
                                    ksk_level, rng);
}

template <typename RNG>
KeySwitchingKey KeySwitchingKey::create_with_std_rng_bridge(
    const SecretKey &secret_key, const ::bfv::math::rq::Poly &from,
    size_t ciphertext_level, size_t ksk_level, RNG &rng) {
  // Forward to the std::mt19937_64 implementation
  std::mt19937_64 mt_rng;
  // Copy state from the input RNG (simplified approach)
  mt_rng.seed(rng());
  return create(secret_key, from, ciphertext_level, ksk_level, mt_rng);
}

}  // namespace bfv
}  // namespace crypto
