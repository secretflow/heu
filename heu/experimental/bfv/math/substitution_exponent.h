#ifndef SUBSTITUTION_EXPONENT_H
#define SUBSTITUTION_EXPONENT_H

#include <cstdint>
#include <memory>
#include <vector>

#include "math/context.h"

namespace bfv::math::rq {

/**
 * @brief Substitution exponent for polynomial substitution operations.
 *
 * storing an exponent and precomputed power_bitrev vector for efficient
 * substitution operations x -> x^exponent.
 */
class SubstitutionExponent {
 public:
  /**
   * @brief Create a substitution exponent from an exponent value.
   *
   * @param ctx The context for the substitution
   * @param exponent The substitution exponent (must be odd modulo 2*degree)
   * @return std::unique_ptr<SubstitutionExponent> The created substitution
   * exponent
   * @throws DefaultException if exponent is even modulo 2*degree
   */
  static std::shared_ptr<SubstitutionExponent> create(
      std::shared_ptr<const Context> ctx, size_t exponent);

  ~SubstitutionExponent();

  // Disable copy constructor and assignment
  // Enable copy constructor (shallow copy via shared_ptr)
  SubstitutionExponent(const SubstitutionExponent &) = default;
  SubstitutionExponent &operator=(const SubstitutionExponent &) = default;

  // Enable move constructor and assignment
  SubstitutionExponent(SubstitutionExponent &&) noexcept;
  SubstitutionExponent &operator=(SubstitutionExponent &&) noexcept;

  /**
   * @brief Get the exponent value.
   */
  size_t exponent() const;

  /**
   * @brief Get the precomputed power_bitrev vector.
   *
   * This vector contains precomputed values for efficient substitution.
   */
  const std::vector<size_t> &power_bitrev() const;

  /**
   * @brief Get the precomputed sign vector for NTT automorphism.
   *
   * Returns true for indices that need to be negated after permutation.
   */
  const std::vector<bool> &power_bitrev_sign() const;

  /**
   * @brief Get the associated context.
   */
  std::shared_ptr<const Context> context() const;

 private:
  class Impl;
  std::shared_ptr<Impl> pimpl_;

  // Private constructor for PIMPL
  explicit SubstitutionExponent(std::shared_ptr<Impl> impl);
};

}  // namespace bfv::math::rq
#endif  // SUBSTITUTION_EXPONENT_H
