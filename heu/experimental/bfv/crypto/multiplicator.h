#pragma once

#include <memory>
#include <vector>

#include "crypto/exceptions.h"
#include "math/basis_mapper.h"
#include "math/context.h"
#include "math/scaling_factor.h"

// Forward declarations
namespace crypto {
namespace bfv {
class BfvParameters;
class Ciphertext;
class RelinearizationKey;
}  // namespace bfv
}  // namespace crypto

namespace crypto {
namespace bfv {

/**
 * @brief Multiplicator that implements a strategy for multiplying ciphertexts.
 *
 * The multiplicator allows specifying:
 * - Whether left-hand side must be scaled
 * - Whether right-hand side must be scaled
 * - The basis at which multiplication will occur
 * - The scaling factor after multiplication
 * - Whether relinearization should be used
 * - Whether modulus switching should be applied
 */
class Multiplicator {
 public:
  // Destructor
  ~Multiplicator();

  // Disable copy constructor and assignment
  Multiplicator(const Multiplicator &) = delete;
  Multiplicator &operator=(const Multiplicator &) = delete;

  // Enable move constructor and assignment
  Multiplicator(Multiplicator &&) noexcept;
  Multiplicator &operator=(Multiplicator &&) noexcept;

  /**
   * @brief Create a multiplicator using custom scaling factors and extended
   * basis
   * @param lhs_scaling_factor Scaling factor for left-hand side ciphertext
   * @param rhs_scaling_factor Scaling factor for right-hand side ciphertext
   * @param extended_basis Extended basis for multiplication
   * @param post_mul_scaling_factor Scaling factor after multiplication
   * @param parameters BFV parameters
   * @return Created multiplicator
   * @throws ParameterException if parameters are invalid
   * @throws MathException if creation fails
   */
  static std::unique_ptr<Multiplicator> create(
      const ::bfv::math::rns::ScalingFactor &lhs_scaling_factor,
      const ::bfv::math::rns::ScalingFactor &rhs_scaling_factor,
      const std::vector<uint64_t> &extended_basis,
      const ::bfv::math::rns::ScalingFactor &post_mul_scaling_factor,
      std::shared_ptr<BfvParameters> parameters);

  /**
   * @brief Create a multiplicator at a specific level
   * @param lhs_scaling_factor Scaling factor for left-hand side ciphertext
   * @param rhs_scaling_factor Scaling factor for right-hand side ciphertext
   * @param extended_basis Extended basis for multiplication
   * @param post_mul_scaling_factor Scaling factor after multiplication
   * @param level Level at which to perform multiplication
   * @param parameters BFV parameters
   * @return Created multiplicator
   * @throws ParameterException if parameters are invalid
   * @throws MathException if creation fails
   */
  static std::unique_ptr<Multiplicator> create_leveled(
      const ::bfv::math::rns::ScalingFactor &lhs_scaling_factor,
      const ::bfv::math::rns::ScalingFactor &rhs_scaling_factor,
      const std::vector<uint64_t> &extended_basis,
      const ::bfv::math::rns::ScalingFactor &post_mul_scaling_factor,
      size_t level, std::shared_ptr<BfvParameters> parameters);

  /**
   * @brief Create a default multiplicator using relinearization
   * @param relinearization_key Relinearization key to use
   * @return Created multiplicator with default settings
   * @throws ParameterException if relinearization key is invalid
   * @throws MathException if creation fails
   */
  static std::unique_ptr<Multiplicator> create_default(
      const RelinearizationKey &relinearization_key);

  /**
   * @brief Enable relinearization after multiplication
   * @param relinearization_key Relinearization key to use
   * @throws ParameterException if relinearization key context doesn't match
   */
  void enable_relinearization(const RelinearizationKey &relinearization_key);

  /**
   * @brief Enable modulus switching after multiplication (and relinearization
   * if applicable)
   * @throws ParameterException if already at the last level
   */
  void enable_mod_switching();

  /**
   * @brief Multiply two ciphertexts using the defined multiplication strategy
   * @param lhs Left-hand side ciphertext
   * @param rhs Right-hand side ciphertext
   * @return Result of multiplication
   * @throws ParameterException if ciphertexts have incompatible parameters or
   * levels
   * @throws MathException if multiplication fails
   */
  Ciphertext multiply(const Ciphertext &lhs, const Ciphertext &rhs) const;

  // Accessors
  /**
   * @brief Get the BFV parameters
   * @return Shared pointer to parameters
   */
  std::shared_ptr<BfvParameters> parameters() const;

  /**
   * @brief Get the level at which multiplication is performed
   * @return Multiplication level
   */
  size_t level() const;

  /**
   * @brief Check if relinearization is enabled
   * @return true if relinearization is enabled
   */
  bool has_relinearization() const;

  /**
   * @brief Check if modulus switching is enabled
   * @return true if modulus switching is enabled
   */
  bool has_mod_switching() const;

  // Equality operators
  bool operator==(const Multiplicator &other) const;
  bool operator!=(const Multiplicator &other) const;

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> pImpl;

  // Private constructor for internal use
  explicit Multiplicator(std::unique_ptr<Impl> impl);

  // Internal implementation methods
  static std::unique_ptr<Multiplicator> create_leveled_internal(
      const ::bfv::math::rns::ScalingFactor &lhs_scaling_factor,
      const ::bfv::math::rns::ScalingFactor &rhs_scaling_factor,
      const std::vector<uint64_t> &extended_basis,
      const ::bfv::math::rns::ScalingFactor &post_mul_scaling_factor,
      size_t level, std::shared_ptr<BfvParameters> parameters);

  // Friend classes
  friend class Ciphertext;
};

}  // namespace bfv
}  // namespace crypto
