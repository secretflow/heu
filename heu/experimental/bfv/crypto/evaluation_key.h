#pragma once

#include <cstdint>
#include <memory>
#include <random>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "crypto/exceptions.h"
#include "yacl/base/byte_container_view.h"

// Forward declarations for math components
namespace bfv {
namespace math {
namespace rq {
class Poly;
}  // namespace rq
}  // namespace math
}  // namespace bfv

// Forward declarations for BFV components
namespace crypto {
namespace bfv {
class BfvParameters;
class Ciphertext;
class GaloisKey;
class SecretKey;
}  // namespace bfv
}  // namespace crypto

namespace crypto {
namespace bfv {

/**
 * Evaluation key for the BFV encryption scheme.
 *
 * An evaluation key enables one or several of the following operations:
 * - column rotation
 * - row rotation
 * - oblivious expansion
 * - inner sum
 */
class EvaluationKey {
 public:
  // Destructor
  ~EvaluationKey();

  // Copy constructor and assignment
  EvaluationKey(const EvaluationKey &other);
  EvaluationKey &operator=(const EvaluationKey &other);

  // Move constructor and assignment
  EvaluationKey(EvaluationKey &&other) noexcept;
  EvaluationKey &operator=(EvaluationKey &&other) noexcept;

  // Query methods for supported operations
  /**
   * @brief Reports whether the evaluation key enables to compute an homomorphic
   * inner sums
   * @return true if inner sum is supported, false otherwise
   */
  bool supports_inner_sum() const;

  /**
   * @brief Reports whether the evaluation key enables to rotate the rows of the
   * plaintext
   * @return true if row rotation is supported, false otherwise
   */
  bool supports_row_rotation() const;

  /**
   * @brief Reports whether the evaluation key enables to rotate the columns of
   * the plaintext
   * @param i The rotation index
   * @return true if column rotation by i is supported, false otherwise
   */
  bool supports_column_rotation_by(size_t i) const;

  /**
   * @brief Reports whether the evaluation key supports oblivious expansion
   * @param level The expansion level
   * @return true if expansion at level is supported, false otherwise
   */
  bool supports_expansion(size_t level) const;

  // Operation methods
  /**
   * @brief Computes the homomorphic inner sum
   * @param ct The input ciphertext
   * @return The inner sum result
   * @throws ParameterException if inner sum is not supported
   * @throws MathException if computation fails
   */
  Ciphertext computes_inner_sum(const Ciphertext &ct) const;

  /**
   * @brief Homomorphically rotate the rows of the plaintext
   * @param ct The input ciphertext
   * @return The row-rotated ciphertext
   * @throws ParameterException if row rotation is not supported
   * @throws MathException if computation fails
   */
  Ciphertext rotates_rows(const Ciphertext &ct) const;

  /**
   * @brief Homomorphically rotate the columns of the plaintext
   * @param ct The input ciphertext
   * @param i The rotation index
   * @return The column-rotated ciphertext
   * @throws ParameterException if column rotation by i is not supported
   * @throws MathException if computation fails
   */
  Ciphertext rotates_columns_by(const Ciphertext &ct, size_t i) const;

  /**
   * @brief Obliviously expands the ciphertext
   * @param ct The input ciphertext (must have size 2)
   * @param size The expansion size
   * @return Vector of expanded ciphertexts
   * @throws ParameterException if expansion is not supported or ct size != 2
   * @throws MathException if computation fails
   */
  std::vector<Ciphertext> expands(const Ciphertext &ct, size_t size) const;

  // Accessors
  /**
   * @brief Get the BFV parameters
   * @return Shared pointer to parameters
   */
  std::shared_ptr<BfvParameters> parameters() const;

  /**
   * @brief Get the ciphertext level
   * @return The ciphertext level
   */
  size_t ciphertext_level() const;

  /**
   * @brief Get the evaluation key level
   * @return The evaluation key level
   */
  size_t evaluation_key_level() const;

  /**
   * @brief Check if this evaluation key is empty/uninitialized
   * @return true if empty, false otherwise
   */
  bool empty() const;

  /**
   * @brief Get the Galois keys map (for serialization)
   * @return Reference to the Galois keys map
   */
  const std::unordered_map<size_t, GaloisKey> &galois_keys() const;

  // Equality operators
  bool operator==(const EvaluationKey &other) const;
  bool operator!=(const EvaluationKey &other) const;

  // Serialization methods
  /**
   * @brief Serialize evaluation key to bytes using msgpack
   * @return Serialized evaluation key data as yacl::Buffer
   * @throws SerializationException if serialization fails
   */
  [[nodiscard]] yacl::Buffer Serialize() const;

  /**
   * @brief Deserialize evaluation key from bytes
   * @param in Serialized evaluation key data
   * @param params BFV parameters for reconstruction
   * @throws SerializationException if deserialization fails
   */
  void Deserialize(yacl::ByteContainerView in,
                   std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create evaluation key from serialized bytes
   * @param bytes Serialized evaluation key data
   * @param params BFV parameters for reconstruction
   * @return Deserialized evaluation key
   * @throws SerializationException if deserialization fails
   */
  static EvaluationKey from_bytes(yacl::ByteContainerView bytes,
                                  std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create EvaluationKey from components (for deserialization)
   * @param params BFV parameters
   * @param ciphertext_level Ciphertext level
   * @param evaluation_key_level Evaluation key level
   * @param galois_keys Map of Galois keys
   * @return EvaluationKey constructed from components
   */
  static EvaluationKey from_components(
      std::shared_ptr<BfvParameters> params, size_t ciphertext_level,
      size_t evaluation_key_level,
      std::unordered_map<size_t, GaloisKey> galois_keys);

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> impl_;

  // Private constructor for internal use
  explicit EvaluationKey(std::unique_ptr<Impl> impl);

  // Helper method to construct rotation to Galois key exponent mapping
  static std::shared_ptr<const std::unordered_map<size_t, size_t>>
  build_rotation_exponent_map(std::shared_ptr<BfvParameters> params);

  // Friend class that needs access to internal methods
  friend class EvaluationKeyBuilder;
};

/**
 * Builder for a leveled evaluation key from the secret key.
 */
class EvaluationKeyBuilder {
 public:
  // Destructor
  ~EvaluationKeyBuilder();

  // Copy constructor and assignment
  EvaluationKeyBuilder(const EvaluationKeyBuilder &other);
  EvaluationKeyBuilder &operator=(const EvaluationKeyBuilder &other);

  // Move constructor and assignment
  EvaluationKeyBuilder(EvaluationKeyBuilder &&other) noexcept;
  EvaluationKeyBuilder &operator=(EvaluationKeyBuilder &&other) noexcept;

  // Static factory methods
  /**
   * @brief Creates a new builder from the SecretKey
   * @param sk The secret key
   * @return EvaluationKeyBuilder instance
   * @throws ParameterException if secret key is invalid
   */
  static EvaluationKeyBuilder create(const SecretKey &sk);

  /**
   * @brief Creates a new builder from the SecretKey for leveled operations
   * @param sk The secret key
   * @param ciphertext_level Level for ciphertext operations
   * @param evaluation_key_level Level for evaluation key
   * @return EvaluationKeyBuilder instance
   * @throws ParameterException if levels are invalid
   */
  static EvaluationKeyBuilder create_leveled(const SecretKey &sk,
                                             size_t ciphertext_level,
                                             size_t evaluation_key_level);

  // Configuration methods (following builder pattern)
  /**
   * @brief Allow expansion by this evaluation key
   * @param level The expansion level
   * @return Reference to this builder for chaining
   * @throws ParameterException if level is invalid
   */
  EvaluationKeyBuilder &enable_expansion(size_t level);

  /**
   * @brief Allow this evaluation key to compute homomorphic inner sums
   * @return Reference to this builder for chaining
   */
  EvaluationKeyBuilder &enable_inner_sum();

  /**
   * @brief Allow this evaluation key to homomorphically rotate the plaintext
   * rows
   * @return Reference to this builder for chaining
   */
  EvaluationKeyBuilder &enable_row_rotation();

  /**
   * @brief Allow this evaluation key to homomorphically rotate the plaintext
   * columns
   * @param i The column rotation index
   * @return Reference to this builder for chaining
   * @throws ParameterException if column index is invalid
   */
  EvaluationKeyBuilder &enable_column_rotation(size_t i);

  /**
   * @brief Build an EvaluationKey with the specified attributes
   * @tparam RNG Random number generator type
   * @param rng Random number generator
   * @return The constructed EvaluationKey
   * @throws MathException if key generation fails
   */
  template <typename RNG>
  EvaluationKey build(RNG &rng);

  /**
   * @brief Build an EvaluationKey with the specified attributes using
   * std::mt19937_64
   * @param rng Random number generator
   * @return The constructed EvaluationKey
   * @throws MathException if key generation fails
   */
  EvaluationKey build(std::mt19937_64 &rng);

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> impl_;

  // Private constructor for internal use
  explicit EvaluationKeyBuilder(std::unique_ptr<Impl> impl);
};

}  // namespace bfv
}  // namespace crypto

// Include template implementations
#include "crypto/evaluation_key_impl.h"
