#pragma once

#include "crypto/public_key.h"
#include "crypto/secret_key.h"

namespace crypto {
namespace bfv {

// Template implementations for PublicKey

template <typename RNG>
PublicKey PublicKey::from_secret_key(const SecretKey &secret_key, RNG &rng) {
  // Forward to the implementation method
  return from_secret_key(secret_key, static_cast<std::mt19937_64 &>(rng));
}

template <typename RNG>
Ciphertext PublicKey::encrypt(const Plaintext &plaintext, RNG &rng) const {
  return encrypt_impl(plaintext, rng);
}

template <typename RNG>
Ciphertext PublicKey::encrypt_impl(const Plaintext &plaintext, RNG &rng) const {
  // This is a template implementation that forwards to the concrete
  // implementation We need to convert the generic RNG to std::mt19937_64 for
  // the actual implementation

  // Create a new mt19937_64 RNG and seed it from the input RNG
  std::mt19937_64 mt_rng;

  // Generate a seed from the input RNG
  std::uniform_int_distribution<uint64_t> dist;
  uint64_t seed = dist(rng);
  mt_rng.seed(seed);

  // Call the concrete implementation
  return encrypt(plaintext, mt_rng);
}

}  // namespace bfv
}  // namespace crypto
