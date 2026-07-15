#pragma once

#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include "crypto/exceptions.h"
#include "crypto/key_switching_key.h"
#include "yacl/base/byte_container_view.h"

// Forward declarations for math components
namespace bfv {
namespace math {
namespace rq {
class Poly;
class SubstitutionExponent;
}  // namespace rq
}  // namespace math
}  // namespace bfv

// Forward declarations for BFV components
namespace crypto {
namespace bfv {
class BfvParameters;
class Ciphertext;
class SecretKey;
}  // namespace bfv
}  // namespace crypto

namespace crypto {
namespace bfv {

/**
 * Galois key for the BFV encryption scheme.
 *
 * A Galois key is a special type of key switching key,
 * which switches from s(x^i) to s(x) where s(x) is the secret key.
 * This enables automorphism operations such as rotations and conjugations.
 */
class GaloisKey {
 public:
  // Destructor
  ~GaloisKey();

  // Copy constructor and assignment
  GaloisKey(const GaloisKey &other);
  GaloisKey &operator=(const GaloisKey &other);

  // Move constructor and assignment
  GaloisKey(GaloisKey &&other) noexcept;
  GaloisKey &operator=(GaloisKey &&other) noexcept;

  // Static factory methods for key generation
  /**
   * @brief Generate a new GaloisKey from a SecretKey
   * @tparam RNG Random number generator type (must satisfy CryptoRng
   * requirements)
   * @param secret_key The secret key to generate from
   * @param exponent The Galois element exponent (must be odd)
   * @param ciphertext_level The ciphertext level
   * @param galois_key_level The Galois key level
   * @param rng Random number generator
   * @return Generated Galois key
   * @throws ParameterException if parameters are invalid or exponent is even
   * @throws MathException if generation fails
   */
  template <typename RNG>
  static GaloisKey create(const SecretKey &secret_key, size_t exponent,
                          size_t ciphertext_level, size_t galois_key_level,
                          RNG &rng);

  /**
   * @brief Generate a new GaloisKey from a SecretKey using std::mt19937_64
   * @param secret_key The secret key to generate from
   * @param exponent The Galois element exponent (must be odd)
   * @param ciphertext_level The ciphertext level
   * @param galois_key_level The Galois key level
   * @param rng Random number generator
   * @return Generated Galois key
   * @throws ParameterException if parameters are invalid or exponent is even
   * @throws MathException if generation fails
   */
  static GaloisKey create(const SecretKey &secret_key, size_t exponent,
                          size_t ciphertext_level, size_t galois_key_level,
                          std::mt19937_64 &rng);

  // Galois operation methods
  /**
   * @brief Apply the keyed automorphism to a ciphertext
   * @param ciphertext The input ciphertext (must have exactly 2 polynomials)
   * @return The transformed ciphertext after automorphism and key switching
   * @throws ParameterException if parameters don't match or ciphertext has
   * wrong size
   * @throws MathException if the keyed automorphism fails
   */
  Ciphertext apply(const Ciphertext &ciphertext) const;

  // Accessors
  /**
   * @brief Get the BFV parameters
   * @return Shared pointer to parameters
   */
  std::shared_ptr<BfvParameters> parameters() const;

  /**
   * @brief Get the Galois element exponent
   * @return The exponent
   */
  size_t exponent() const;

  /**
   * @brief Get the ciphertext level
   * @return The ciphertext level
   */
  size_t ciphertext_level() const;

  /**
   * @brief Get the Galois key level
   * @return The Galois key level
   */
  size_t galois_key_level() const;

  /**
   * @brief Check if this Galois key is empty/uninitialized
   * @return true if empty, false otherwise
   */
  bool empty() const;

  /**
   * @brief Get the underlying KeySwitchingKey (for advanced use)
   * @return Reference to the key switching key
   */
  const KeySwitchingKey &key_switching_key() const;

  // Equality operators
  bool operator==(const GaloisKey &other) const;
  bool operator!=(const GaloisKey &other) const;

  // Serialization methods
  /**
   * @brief Serialize Galois key to bytes using msgpack
   * @return Serialized Galois key data as yacl::Buffer
   * @throws SerializationException if serialization fails
   */
  [[nodiscard]] yacl::Buffer Serialize() const;

  /**
   * @brief Deserialize Galois key from bytes
   * @param in Serialized Galois key data
   * @param params BFV parameters for reconstruction
   * @throws SerializationException if deserialization fails
   */
  void Deserialize(yacl::ByteContainerView in,
                   std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create Galois key from serialized bytes
   * @param bytes Serialized Galois key data
   * @param params BFV parameters for reconstruction
   * @return Deserialized Galois key
   * @throws SerializationException if deserialization fails
   */
  static GaloisKey from_bytes(yacl::ByteContainerView bytes,
                              std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create GaloisKey from components (for deserialization)
   * @param key_switching_key Key switching key
   * @param exponent Galois exponent
   * @param params BFV parameters
   * @return GaloisKey constructed from components
   */
  static GaloisKey from_components(KeySwitchingKey key_switching_key,
                                   size_t exponent,
                                   std::shared_ptr<BfvParameters> params);

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> impl_;

  // Private constructor for internal use
  explicit GaloisKey(std::unique_ptr<Impl> impl);

  // Friend classes that need access to internal methods
  friend class EvaluationKey;
};

}  // namespace bfv
}  // namespace crypto

// Include template implementations
#include "crypto/galois_key_impl.h"
