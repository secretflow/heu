#ifndef PULSAR_MATH_RQ_POLY_H
#define PULSAR_MATH_RQ_POLY_H

#include <array>
#include <memory>
#include <vector>

#include "math/biguint.h"
#include "math/representation.h"
#include "math/substitution_exponent.h"
#include "util/arena_allocator.h"

namespace bfv::math::rq {
class Context;
class BasisMapper;
class ContextTransfer;
}  // namespace bfv::math::rq

// ... (in Poly class)

namespace bfv::math::rq {

class Poly {
 public:
  // ... constructors ...
  using ArenaHandle = ::bfv::util::ArenaHandle;

  Poly();
  ~Poly();

  Poly(const Poly &other);
  Poly &operator=(const Poly &other);
  Poly(Poly &&);
  Poly &operator=(Poly &&);

  static Poly zero(std::shared_ptr<const Context> ctx,
                   Representation representation,
                   ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  static Poly uninitialized(
      std::shared_ptr<const Context> ctx, Representation representation,
      ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  // ... random ...
  template <typename RNG>
  static Poly random(std::shared_ptr<const Context> ctx,
                     Representation representation, RNG &rng,
                     ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  static Poly random_from_seed(
      std::shared_ptr<const Context> ctx, Representation representation,
      const std::array<uint8_t, 32> &seed,
      ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  template <typename RNG>
  static Poly small(std::shared_ptr<const Context> ctx,
                    Representation representation, size_t variance, RNG &rng,
                    ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  // ...

  // Access to raw data pointers
  const uint64_t *data(size_t modulus_index) const;
  uint64_t *data(size_t modulus_index);

  // Access to cached multiply-hint data pointers when present.
  const uint64_t *data_shoup(size_t modulus_index) const;
  uint64_t *data_shoup(size_t modulus_index);

  /**
   * @brief Return a copy of all residue rows.
   * @note Provided for compatibility. Prefer raw row access for hot paths.
   */
  std::vector<std::vector<uint64_t>> coefficients() const;

  // Helper to check whether cached multiply hints are materialized.
  bool has_shoup_coefficients() const;

  // ...

  /**
   * @brief Returns the representation of the polynomial.
   */
  Representation representation() const;

  /**
   * @brief Force the representation tag without transforming stored data.
   * WARNING: This only updates metadata.
   */
  void override_representation(Representation to);

  /**
   * @brief Allow non-constant-time arithmetic shortcuts.
   */
  void allow_variable_time_computations();

  /**
   * @brief Enable relaxed arithmetic paths for internal kernels.
   */
  void enable_relaxed_arithmetic() { allow_variable_time_computations(); }

  /**
   * @brief Require constant-time arithmetic paths.
   */
  void disallow_variable_time_computations();

  /**
   * @brief Disable relaxed arithmetic paths for internal kernels.
   */
  void disable_relaxed_arithmetic() { disallow_variable_time_computations(); }

  /**
   * @brief Report whether non-constant-time arithmetic is enabled.
   */
  bool allows_variable_time_computations() const;

  /**
   * @brief Report whether relaxed arithmetic paths are enabled.
   */
  bool uses_relaxed_arithmetic() const {
    return allows_variable_time_computations();
  }

  /**
   * @brief Remap the polynomial into another ring context.
   */
  Poly remap_to_context(const ContextTransfer &transfer) const;

  /**
   * @brief Map a polynomial through a basis mapper.
   */
  Poly map_to(const BasisMapper &mapper) const;

  /**
   * @brief Remap the polynomial through a basis transfer service.
   */
  Poly remap_to_basis(const BasisMapper &mapper) const {
    return map_to(mapper);
  }

  /**
   * @brief Apply the automorphism `x -> x^i` to the stored polynomial.
   *
   * In PowerBasis representation, `i` can be any integer not divisible by
   * `2 * degree`. In Ntt and NttShoup representation, `i` must be odd and
   * not divisible by `2 * degree`.
   */
  Poly substitute(const SubstitutionExponent &i) const;

  /**
   * @brief Apply a ring automorphism to the stored polynomial.
   */
  Poly apply_automorphism(const SubstitutionExponent &i) const {
    return substitute(i);
  }

  /**
   * @brief Drop the tail residue channel after dividing and rounding each
   * coefficient by the removed modulus.
   *
   * Returns an error if the context chain has no lower level or if the
   * polynomial is not stored in PowerBasis form.
   */
  /**
   * @brief Drop the last residue channel and descend one ring level.
   */
  void drop_last_residue();

  /**
   * @brief Repeatedly drop tail residue channels until a requested lower ring
   * context is reached.
   *
   * Returns an error if the requested context is not reachable by repeatedly
   * removing the tail modulus, or if the polynomial is not in PowerBasis.
   */
  /**
   * @brief Repeatedly drop residue channels until a target context is reached.
   */
  void drop_to_context(std::shared_ptr<const Context> context);

  /**
   * @brief Return the ring context of the polynomial storage.
   */
  std::shared_ptr<const Context> ctx() const;

  /**
   * @brief Multiply a PowerBasis polynomial by `x^(-power)`.
   */
  void multiply_inverse_power_of_x(size_t power);

  /**
   * @brief Change the representation of the polynomial.
   */
  void change_representation(Representation to);

  // Equality comparison
  bool operator==(const Poly &other) const;
  bool operator!=(const Poly &other) const;

  // Type conversion methods
  std::vector<uint64_t> to_u64_vector() const;
  std::vector<::bfv::math::rns::BigUint> to_biguint_vector() const;

  // Serialization methods
  std::vector<uint8_t> to_bytes() const;
  static Poly from_bytes(const std::vector<uint8_t> &bytes,
                         std::shared_ptr<const Context> ctx,
                         ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  // Static factory methods for type conversion
  static Poly from_u64_vector(const std::vector<uint64_t> &coeffs,
                              std::shared_ptr<const Context> ctx,
                              bool variable_time, Representation representation,
                              bool has_lazy_coefficients = false);

  static Poly from_i64_vector(const std::vector<int64_t> &coeffs,
                              std::shared_ptr<const Context> ctx,
                              bool variable_time,
                              Representation representation);

  static Poly from_biguint_vector(
      const std::vector<::bfv::math::rns::BigUint> &coeffs,
      std::shared_ptr<const Context> ctx, bool variable_time,
      Representation representation);

  static Poly from_coefficients(
      const std::vector<std::vector<uint64_t>> &coeffs,
      std::shared_ptr<const Context> ctx, bool variable_time = false,
      Representation representation = Representation::PowerBasis,
      bool has_lazy_coefficients = false);

  /**
   * @brief Create a constant NTT polynomial with deferred coefficient
   * reduction.
   *
   * The returned polynomial is tagged for non-constant-time arithmetic and
   * preserves deferred modular reduction.
   *
   * @param power_basis_coefficients Coefficients given in power-basis order
   * @param ctx Ring context for the output polynomial
   * @return Poly Polynomial in NTT form with deferred reduction enabled
   */
  static Poly
  create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
      const std::vector<uint64_t> &power_basis_coefficients,
      std::shared_ptr<const Context> ctx);
  static Poly
  create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
      const uint64_t *power_basis_coefficients, size_t coefficient_count,
      std::shared_ptr<const Context> ctx);
  static void
  fill_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
      const uint64_t *power_basis_coefficients, size_t coefficient_count,
      Poly &out);
  static void
  fill_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
      const uint64_t *power_basis_coefficients, size_t coefficient_count,
      size_t source_modulus_index, Poly &out);
  static void
  fill_constant_ntt_polynomial4_with_lazy_coefficients_and_variable_time(
      const uint64_t *coeff0, const uint64_t *coeff1, const uint64_t *coeff2,
      const uint64_t *coeff3, size_t coefficient_count, Poly &out0, Poly &out1,
      Poly &out2, Poly &out3);
  static void
  fill_constant_ntt_polynomial4_with_lazy_coefficients_and_variable_time(
      const uint64_t *coeff0, const uint64_t *coeff1, const uint64_t *coeff2,
      const uint64_t *coeff3, size_t coefficient_count, size_t source_index0,
      size_t source_index1, size_t source_index2, size_t source_index3,
      Poly &out0, Poly &out1, Poly &out2, Poly &out3);

  /**
   * @brief Fused tensor product used by ciphertext-ciphertext multiplication.
   *
   * Computes the three NTT-domain product limbs in place:
   * `c0 = c00 * c10`
   * `c1 = c00 * c11 + c01 * c10`
   * `c2 = c01 * c11`
   *
   * Updates `c00` and `c01` and writes the final limb into `c2`.
   * All inputs must share the same ring context and NTT storage form.
   */
  static void tensor_product_inplace(Poly &c00, Poly &c01, Poly &c2,
                                     const Poly &c10, const Poly &c11);

  /**
   * @brief Computes `*this = *this + factor * term`.
   *
   * Performs fused multiply-add without allocating a temporary product.
   * Uses cached multiply hints when `term` carries the `NttShoup` tag.
   */
  void multiply_accumulate(const Poly &factor, const Poly &term);

 private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;

  // Private constructor for PIMPL
  explicit Poly(std::unique_ptr<Impl> impl);

  // Friend declarations for external functions
  friend class BasisMapper;
  friend class ContextTransfer;

  // Internal constructor for creating polynomials from coefficient matrix
  static Poly from_coefficients_internal(
      std::shared_ptr<const Context> ctx, Representation representation,
      bool allow_variable_time,
      std::vector<std::vector<uint64_t>> &&coefficients,
      bool has_lazy_coefficients);

  // Friend declarations for arithmetic operations
  friend Poly &operator+=(Poly &lhs, const Poly &rhs);
  friend Poly &operator-=(Poly &lhs, const Poly &rhs);
  friend Poly &operator*=(Poly &lhs, const Poly &rhs);
  friend Poly &operator*=(Poly &lhs, const ::bfv::math::rns::BigUint &scalar);
  friend Poly operator-(const Poly &poly);

  // Binary operators
  friend Poly operator+(const Poly &lhs, const Poly &rhs);
  friend Poly operator-(const Poly &lhs, const Poly &rhs);
  friend Poly operator*(const Poly &lhs, const Poly &rhs);
  friend Poly operator*(const Poly &lhs,
                        const ::bfv::math::rns::BigUint &scalar);
  friend Poly operator*(const ::bfv::math::rns::BigUint &scalar,
                        const Poly &rhs);

  friend Poly dot_product(
      const std::vector<std::reference_wrapper<const Poly>> &p,
      const std::vector<std::reference_wrapper<const Poly>> &q);
};

/**
 * @brief Compute dot product of two polynomial vectors.
 */
Poly dot_product(const std::vector<std::reference_wrapper<const Poly>> &p,
                 const std::vector<std::reference_wrapper<const Poly>> &q);

}  // namespace bfv::math::rq
#endif  // POLY_H
