#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "util/arena_allocator.h"
#include "yacl/base/byte_container_view.h"

// Forward declarations for math library components
namespace bfv::math::rq {
class Poly;
class Context;
}  // namespace bfv::math::rq

namespace crypto {
namespace bfv {

// Forward declarations
class BfvParameters;
class Plaintext;

/**
 * A ciphertext encrypting a plaintext in the BFV encryption scheme.
 *
 * This class represents encrypted data that can be operated on homomorphically.
 * It maintains level information for modulus switching and supports various
 * homomorphic operations like addition, subtraction, and multiplication.
 */
class Ciphertext {
 public:
  // Constructor and destructor
  /**
   * @brief Default constructor - creates an empty ciphertext
   */
  Ciphertext();

  /**
   * @brief Destructor
   */
  ~Ciphertext();

  // Copy and move semantics
  Ciphertext(const Ciphertext &other);
  Ciphertext &operator=(const Ciphertext &other);
  Ciphertext(Ciphertext &&other) noexcept;
  Ciphertext &operator=(Ciphertext &&other) noexcept;

  // Equality comparison
  /**
   * @brief Equality comparison
   */
  bool operator==(const Ciphertext &other) const;
  bool operator!=(const Ciphertext &other) const;

  // Static factory methods
  /**
   * @brief Create a ciphertext from a vector of polynomials
   * A ciphertext must contain at least two polynomials, and all polynomials
   * must have the same representation and the same context.
   * @param polynomials Vector of polynomials (must have at least 2 elements)
   * @param params BFV parameters
   * @return Created ciphertext
   * @throws ParameterException if polynomials are invalid
   */
  static Ciphertext from_polynomials(
      const std::vector<::bfv::math::rq::Poly> &polynomials,
      std::shared_ptr<BfvParameters> params,
      ::bfv::util::ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());
  static Ciphertext from_polynomials(
      std::vector<::bfv::math::rq::Poly> &&polynomials,
      std::shared_ptr<BfvParameters> params,
      ::bfv::util::ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  /**
   * @brief Create a ciphertext from a vector of polynomials with explicit level
   * A ciphertext must contain at least two polynomials, and all polynomials
   * must have the same representation and the same context.
   * @param polynomials Vector of polynomials (must have at least 2 elements)
   * @param params BFV parameters
   * @param level Explicit level for the ciphertext
   * @return Created ciphertext
   * @throws ParameterException if polynomials are invalid
   */
  static Ciphertext from_polynomials_with_level(
      const std::vector<::bfv::math::rq::Poly> &polynomials,
      std::shared_ptr<BfvParameters> params, size_t level,
      ::bfv::util::ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());
  static Ciphertext from_polynomials_with_level(
      std::vector<::bfv::math::rq::Poly> &&polynomials,
      std::shared_ptr<BfvParameters> params, size_t level,
      ::bfv::util::ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  /**
   * @brief Generate the zero ciphertext
   * @param params BFV parameters
   * @return Zero ciphertext
   */
  static Ciphertext zero(
      std::shared_ptr<BfvParameters> params,
      ::bfv::util::ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  // Level management
  /**
   * @brief Modulo switch the ciphertext to the last level
   * @throws MathException if operation fails
   */
  void mod_switch_to_last_level();

  /**
   * @brief Modulo switch the ciphertext to the next level
   * @throws MathException if operation fails
   */
  void mod_switch_to_next_level();

  /**
   * @brief Get the current level of this ciphertext
   * @return The level
   */
  size_t level() const;

  /**
   * @brief Get the number of polynomials in this ciphertext
   * @return Number of polynomials
   */
  size_t size() const;

  /**
   * @brief Check if this ciphertext is empty/uninitialized
   * @return true if empty, false otherwise
   */
  bool empty() const;

  /**
   * @brief Get the BFV parameters
   * @return Shared pointer to parameters
   */
  std::shared_ptr<BfvParameters> parameters() const;

  /**
   * @brief Add another ciphertext to this one in-place
   * @param other Ciphertext to add
   * @throws ParameterException if parameters mismatch
   */
  void add_inplace(const Ciphertext &other);

  /**
   * @brief Subtract another ciphertext from this one in-place
   * @param other Ciphertext to subtract
   * @throws ParameterException if parameters mismatch
   */
  void sub_inplace(const Ciphertext &other);

  // Note: Homomorphic operations are implemented in operators.h/operators.cc

  // Access to internal polynomials (for advanced operations)
  /**
   * @brief Get read-only access to the polynomial at the given index
   * @param index Index of the polynomial
   * @return Reference to the polynomial
   * @throws std::out_of_range if index is invalid
   */
  const ::bfv::math::rq::Poly &polynomial(size_t index) const;

  /**
   * @brief Get all polynomials (read-only)
   * @return Vector of polynomials
   */
  const std::vector<::bfv::math::rq::Poly> &polynomials() const;

  // Seed management (for compressed representation)
  /**
   * @brief Check if this ciphertext has a seed (compressed representation)
   * @return true if has seed, false otherwise
   */
  bool has_seed() const;

  /**
   * @brief Get the seed if available
   * @return Optional seed array
   */
  std::optional<std::array<uint8_t, 32>> seed() const;

  // Serialization methods
  /**
   * @brief Serialize ciphertext to bytes using msgpack
   * @return Serialized ciphertext data as yacl::Buffer
   * @throws SerializationException if serialization fails
   */
  [[nodiscard]] yacl::Buffer Serialize() const;

  /**
   * @brief Deserialize ciphertext from bytes
   * @param in Serialized ciphertext data
   * @param params BFV parameters for reconstruction
   * @throws SerializationException if deserialization fails
   */
  void Deserialize(
      yacl::ByteContainerView in, std::shared_ptr<BfvParameters> params,
      ::bfv::util::ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  /**
   * @brief Create ciphertext from serialized bytes
   * @param bytes Serialized ciphertext data
   * @param params BFV parameters for reconstruction
   * @return Deserialized ciphertext
   * @throws SerializationException if deserialization fails
   */
  static Ciphertext from_bytes(
      yacl::ByteContainerView bytes, std::shared_ptr<BfvParameters> params,
      ::bfv::util::ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> pImpl;

  // Private constructor for internal use
  explicit Ciphertext(std::unique_ptr<Impl> impl);

  // Internal methods for operations
  void truncate(size_t len);

  // Methods for relinearization support
  ::bfv::math::rq::Poly &mutable_component(size_t index);
  void add_to_component(size_t index, const ::bfv::math::rq::Poly &poly);
  void truncate_to_size(size_t new_size);

  // Seed management (for friend classes)
  void set_seed(const std::array<uint8_t, 32> &seed);

  // Friend classes that need access to internal methods
  friend class SecretKey;
  friend class PublicKey;
  friend class RelinearizationKey;
  friend class EvaluationKey;
  friend class Multiplicator;
};

// Note: Non-member operators are implemented in operators.h/operators.cc

}  // namespace bfv
}  // namespace crypto
