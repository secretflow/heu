#pragma once

#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include "crypto/exceptions.h"
#include "crypto/serialization/serialization_exceptions.h"
#include "yacl/base/byte_container_view.h"

// Forward declarations for math library components
namespace bfv::math::rq {
class Context;
class Poly;
class BasisMapper;
}  // namespace bfv::math::rq

namespace bfv::math::rns {
enum class RnsScalingScheme;
}  // namespace bfv::math::rns

namespace bfv::math::ntt {
class NttOperator;
}

namespace bfv::math::zq {
class Modulus;
}

namespace crypto {
namespace bfv {

// Forward declaration
class BfvParametersBuilder;

/**
 * Parameters for the BFV encryption scheme.
 *
 * This class holds all the parameters needed for BFV homomorphic encryption,
 * including polynomial degree, plaintext modulus, ciphertext moduli, and
 * various precomputed values for efficient operations.
 */
class BfvParameters {
 public:
  // Constructor and destructor
  BfvParameters();
  ~BfvParameters();

  // Copy and move semantics
  BfvParameters(const BfvParameters &other);
  BfvParameters &operator=(const BfvParameters &other);
  BfvParameters(BfvParameters &&other) noexcept;
  BfvParameters &operator=(BfvParameters &&other) noexcept;

  // Equality comparison
  bool operator==(const BfvParameters &other) const;
  bool operator!=(const BfvParameters &other) const;

  // Core accessors
  /**
   * @brief Returns the underlying polynomial degree
   */
  size_t degree() const;

  /**
   * @brief Returns the plaintext modulus
   */
  uint64_t plaintext_modulus() const;

  /**
   * @brief Returns a reference to the ciphertext moduli
   */
  const std::vector<uint64_t> &moduli() const;

  /**
   * @brief Returns a reference to the ciphertext moduli sizes
   */
  const std::vector<size_t> &moduli_sizes() const;

  /**
   * @brief Returns the maximum level allowed by these parameters
   */
  size_t max_level() const;

  /**
   * @brief Returns the error variance parameter
   */
  size_t variance() const;

  /**
   * @brief Returns the compile-time RNS multiplication scheme (Projection or
   * AuxBase).
   */
  ::bfv::math::rns::RnsScalingScheme mul_rns_scaling_scheme() const;

  // Context management
  /**
   * @brief Returns the context corresponding to the level
   * @param level The level (0 to max_level())
   * @return Shared pointer to the context
   * @throws ParameterException if level is invalid
   */
  std::shared_ptr<::bfv::math::rq::Context> ctx_at_level(size_t level) const;

  /**
   * @brief Returns the level of a given context
   * @param ctx The context to find the level for
   * @return The level corresponding to the context
   * @throws ParameterException if context is not found
   */
  size_t level_of_ctx(
      const std::shared_ptr<::bfv::math::rq::Context> &ctx) const;

  /**
   * @brief Get the basis mapper for a specific level (internal use)
   * @param level The level
   * @return Shared pointer to the basis mapper
   * @throws ParameterException if level is invalid
   */
  std::shared_ptr<::bfv::math::rq::BasisMapper> plaintext_mapper_at_level(
      size_t level) const;

  /**
   * @brief Get the delta polynomial for a specific level (internal use)
   * @param level The level
   * @return Reference to the delta polynomial
   * @throws ParameterException if level is invalid
   */
  const ::bfv::math::rq::Poly &delta_at_level(size_t level) const;

  /**
   * @brief Get the q_mod_t value for a specific level (internal use)
   * @param level The level
   * @return The q_mod_t value
   * @throws ParameterException if level is invalid
   */
  uint64_t q_mod_t_at_level(size_t level) const;

  /**
   * @brief Get the matrix representation index map for SIMD encoding
   * @return Reference to the matrix representation index map
   */
  const std::vector<size_t> &matrix_reps_index_map() const;

  /**
   * @brief Get the NTT operator for plaintext operations
   * @return Shared pointer to the NTT operator (may be null)
   */
  std::shared_ptr<::bfv::math::ntt::NttOperator> ntt_operator() const;

  /**
   * @brief Generate a random vector using the plaintext modulus
   * @param size Size of the vector to generate
   * @param rng Random number generator
   * @return Vector of random values modulo plaintext modulus
   */
  std::vector<uint64_t> plaintext_random_vec(size_t size,
                                             std::mt19937_64 &rng) const;

  /**
   * @brief Self-test parameters by performing a simple encrypt-decrypt cycle.
   * Note: This strictly requires that the context includes encryption support
   * (e.g. key generator, encryptor). However, BfvParameters is just data.
   * The request is to verify the *parameters* are usable.
   * Since this class doesn't depend on Encryptor/Decryptor, we can't fully test
   * encryption here without circular dependencies if we aren't careful.
   *
   * Actually, the implementation plan meant "BfvParameters::SelfTest()".
   * Use forward declarations or include strictly necessary headers in .cc.
   *
   * @param detailed_report Optional string pointer to write report to
   * @return true if self-test passed
   */
  bool SelfTest(std::string *detailed_report = nullptr) const;

  // Static factory methods
  /**
   * @brief Vector of default parameters providing about 128 bits of security
   * according to the homomorphicencryption.org standard
   * @param plaintext_nbits Number of bits for the plaintext modulus (must be <
   * 64)
   * @return Vector of parameter sets with different polynomial degrees
   */
  static std::vector<std::shared_ptr<BfvParameters>> default_parameters_128(
      size_t plaintext_nbits);

  /**
   * @brief Create default parameters for testing
   * @param num_moduli Number of ciphertext moduli
   * @param degree Polynomial degree (must be power of 2, >= 8)
   * @return Shared pointer to BfvParameters
   */
  static std::shared_ptr<BfvParameters> default_arc(size_t num_moduli,
                                                    size_t degree);

  // Serialization methods
  /**
   * @brief Serialize parameters to bytes using msgpack
   * @return Serialized parameter data as yacl::Buffer
   * @throws SerializationException if serialization fails
   */
  [[nodiscard]] yacl::Buffer Serialize() const;

  /**
   * @brief Deserialize parameters from bytes
   * @param in Serialized parameter data
   * @throws SerializationException if deserialization fails
   */
  void Deserialize(yacl::ByteContainerView in);

  /**
   * @brief Create BfvParameters from serialized bytes
   * @param bytes Serialized parameter data
   * @return Shared pointer to deserialized BfvParameters
   * @throws SerializationException if deserialization fails
   */
  static std::shared_ptr<BfvParameters> from_bytes(
      yacl::ByteContainerView bytes);

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> pImpl;

  // Private constructor for builder
  explicit BfvParameters(std::unique_ptr<Impl> impl);

  friend class BfvParametersBuilder;
};

/**
 * Builder for parameters for the BFV encryption scheme.
 *
 * This class provides a fluent interface for constructing BfvParameters
 * with validation of all input parameters.
 */
class BfvParametersBuilder {
 public:
  /**
   * @brief Creates a new instance of the builder
   */
  BfvParametersBuilder();

  /**
   * @brief Destructor
   */
  ~BfvParametersBuilder();

  // Copy and move semantics
  BfvParametersBuilder(const BfvParametersBuilder &other);
  BfvParametersBuilder &operator=(const BfvParametersBuilder &other);
  BfvParametersBuilder(BfvParametersBuilder &&other) noexcept;
  BfvParametersBuilder &operator=(BfvParametersBuilder &&other) noexcept;

  /**
   * @brief Sets the polynomial degree
   * @param degree Polynomial degree (must be power of 2, >= 8)
   * @return Reference to this builder for chaining
   */
  BfvParametersBuilder &set_degree(size_t degree);

  /**
   * @brief Sets the plaintext modulus
   * @param plaintext Plaintext modulus (must be between 2 and 2^62 - 1)
   * @return Reference to this builder for chaining
   */
  BfvParametersBuilder &set_plaintext_modulus(uint64_t plaintext);

  /**
   * @brief Sets the sizes of the ciphertext moduli
   * Only one of set_moduli_sizes and set_moduli can be specified
   * @param sizes Vector of modulus sizes (each between 10 and 62 bits)
   * @return Reference to this builder for chaining
   */
  BfvParametersBuilder &set_moduli_sizes(const std::vector<size_t> &sizes);

  /**
   * @brief Sets the ciphertext moduli to use
   * Only one of set_moduli_sizes and set_moduli can be specified
   * @param moduli Vector of prime moduli
   * @return Reference to this builder for chaining
   */
  BfvParametersBuilder &set_moduli(const std::vector<uint64_t> &moduli);

  /**
   * @brief Sets the error variance
   * @param variance Error variance (typically between 1 and 16)
   * @return Reference to this builder for chaining
   */
  BfvParametersBuilder &set_variance(size_t variance);

  /**
   * @brief Validates the requested multiplication scheme against compile-time
   * configuration.
   *
   * Runtime switching is disabled. This setter is kept for API compatibility
   * and throws if `scheme` does not match the compile-time selected algorithm.
   * @param scheme RNS scaling scheme (e.g., Projection or AuxBase)
   * @return Reference to this builder for chaining
   */
  BfvParametersBuilder &set_mul_rns_scaling_scheme(
      ::bfv::math::rns::RnsScalingScheme scheme);

  /**
   * @brief Build a new BfvParameters inside a shared_ptr
   * @return Shared pointer to the built parameters
   * @throws ParameterException if parameters are invalid
   */
  std::shared_ptr<BfvParameters> build_arc();

  /**
   * @brief Build a new BfvParameters
   * @return The built parameters
   * @throws ParameterException if parameters are invalid
   */
  BfvParameters build();

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> pImpl;

  /**
   * @brief Generate ciphertext moduli with the specified sizes
   * @param moduli_sizes Vector of modulus sizes
   * @param degree Polynomial degree
   * @return Vector of generated prime moduli
   * @throws ParameterException if generation fails
   */
  static std::vector<uint64_t> generate_moduli(
      const std::vector<size_t> &moduli_sizes, size_t degree);
};

}  // namespace bfv
}  // namespace crypto
