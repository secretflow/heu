#pragma once

#include "crypto/public_key.h"
#include "crypto/rng_bridge.h"
#include "crypto/secret_key.h"

namespace crypto {
namespace bfv {

// Template implementations for PublicKey

template <typename RNG>
PublicKey PublicKey::from_secret_key(const SecretKey &secret_key, RNG &rng) {
  return detail::WithMt19937_64(rng, [&](std::mt19937_64 &std_rng) {
    return from_secret_key(secret_key, std_rng);
  });
}

template <typename RNG>
Ciphertext PublicKey::encrypt(const Plaintext &plaintext, RNG &rng) const {
  return encrypt_impl(plaintext, rng);
}

template <typename RNG>
Ciphertext PublicKey::encrypt_impl(const Plaintext &plaintext, RNG &rng) const {
  return detail::WithMt19937_64(rng, [&](std::mt19937_64 &std_rng) {
    return encrypt(plaintext, std_rng);
  });
}

}  // namespace bfv
}  // namespace crypto
