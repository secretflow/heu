#pragma once

#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include "crypto/exceptions.h"
#include "yacl/base/byte_container_view.h"

// Forward declarations for BFV components
namespace crypto {
namespace bfv {
class BfvParameters;
class Plaintext;
class Ciphertext;
class SecretKey;
}  // namespace bfv
}  // namespace crypto

namespace crypto {
namespace bfv {

/**
 * Public key for the BFV encryption scheme.
 *
 * This class represents a public key used for encryption in the BFV scheme.
 * Public keys can be safely shared and used for encryption, while only the
 * corresponding secret key can decrypt the resulting ciphertexts.
 */
class PublicKey {
 public:
  // Destructor
  ~PublicKey();

  // Copy constructor and assignment
  PublicKey(const PublicKey &other);
  PublicKey &operator=(const PublicKey &other);

  // Move constructor and assignment
  PublicKey(PublicKey &&other) noexcept;
  PublicKey &operator=(PublicKey &&other) noexcept;

  // Static factory methods for key generation
  /**
   * @brief Generate a new PublicKey from a SecretKey
   * @tparam RNG Random number generator type (must satisfy CryptoRng
   * requirements)
   * @param secret_key The secret key to generate from
   * @param rng Random number generator
   * @return Generated public key
   * @throws ParameterException if secret key is invalid
   * @throws MathException if generation fails
   */
  template <typename RNG>
  static PublicKey from_secret_key(const SecretKey &secret_key, RNG &rng);

  /**
   * @brief Generate a new PublicKey from a SecretKey using std::mt19937_64
   * @param secret_key The secret key to generate from
   * @param rng Random number generator
   * @return Generated public key
   * @throws ParameterException if secret key is invalid
   * @throws MathException if generation fails
   */
  static PublicKey from_secret_key(const SecretKey &secret_key,
                                   std::mt19937_64 &rng);

  // Encryption methods
  /**
   * @brief Encrypt a plaintext using the public key
   * @tparam RNG Random number generator type
   * @param plaintext Plaintext to encrypt
   * @param rng Random number generator
   * @return Encrypted ciphertext
   * @throws ParameterException if parameters don't match
   * @throws MathException if encryption fails
   */
  template <typename RNG>
  Ciphertext encrypt(const Plaintext &plaintext, RNG &rng) const;

  /**
   * @brief Encrypt a plaintext using std::mt19937_64
   * @param plaintext Plaintext to encrypt
   * @param rng Random number generator
   * @return Encrypted ciphertext
   * @throws ParameterException if parameters don't match
   * @throws MathException if encryption fails
   */
  Ciphertext encrypt(const Plaintext &plaintext, std::mt19937_64 &rng) const;

  // Accessors
  /**
   * @brief Get the BFV parameters
   * @return Shared pointer to parameters
   */
  std::shared_ptr<BfvParameters> parameters() const;

  /**
   * @brief Check if this public key is empty/uninitialized
   * @return true if empty, false otherwise
   */
  bool empty() const;

  /**
   * @brief Get the internal ciphertext (for advanced use)
   * @return Reference to the internal ciphertext
   */
  const Ciphertext &ciphertext() const;

  // Equality operators
  bool operator==(const PublicKey &other) const;
  bool operator!=(const PublicKey &other) const;

  // Serialization methods
  /**
   * @brief Serialize public key to bytes using msgpack
   * @return Serialized public key data as yacl::Buffer
   * @throws SerializationException if serialization fails
   */
  [[nodiscard]] yacl::Buffer Serialize() const;

  /**
   * @brief Deserialize public key from bytes
   * @param in Serialized public key data
   * @param params BFV parameters for reconstruction
   * @throws SerializationException if deserialization fails
   */
  void Deserialize(yacl::ByteContainerView in,
                   std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create public key from serialized bytes
   * @param bytes Serialized public key data
   * @param params BFV parameters for reconstruction
   * @return Deserialized public key
   * @throws SerializationException if deserialization fails
   */
  static PublicKey from_bytes(yacl::ByteContainerView bytes,
                              std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create PublicKey from ciphertext (for deserialization)
   * @param ciphertext The ciphertext representing the public key
   * @param params BFV parameters
   * @return PublicKey constructed from the ciphertext
   */
  static PublicKey from_ciphertext(Ciphertext ciphertext,
                                   std::shared_ptr<BfvParameters> params);

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> pImpl;

  // Private constructor for internal use
  explicit PublicKey(std::unique_ptr<Impl> impl);

  // Internal implementation for std::mt19937_64
  template <typename RNG>
  Ciphertext encrypt_impl(const Plaintext &plaintext, RNG &rng) const;

  // Friend classes that need access to internal methods
  friend class RelinearizationKey;
  friend class EvaluationKey;
  friend class GaloisKey;
};

}  // namespace bfv
}  // namespace crypto

// Include template implementations
#include "crypto/public_key_impl.h"
