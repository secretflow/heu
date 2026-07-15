#ifndef BASIS_MAPPER_H
#define BASIS_MAPPER_H

#include <memory>

#include "math/context.h"
#include "math/poly.h"
#include "math/scaling_factor.h"

namespace bfv::math::rq {

/**
 * @brief Maps polynomials between related RNS contexts.
 */
class BasisMapper {
 public:
  /**
   * @brief Create a basis mapper from a context `from` to a context `to`.
   *
   * @param from Source context
   * @param to Target context
   * @param factor Scaling factor to apply
   * @return std::unique_ptr<BasisMapper> The created mapper
   * @throws DefaultException if degrees are incompatible
   */
  static std::unique_ptr<BasisMapper> create(
      std::shared_ptr<const Context> from, std::shared_ptr<const Context> to,
      const ::bfv::math::rns::ScalingFactor &factor);

  ~BasisMapper();

  // Disable copy constructor and assignment
  BasisMapper(const BasisMapper &) = delete;
  BasisMapper &operator=(const BasisMapper &) = delete;

  // Enable move constructor and assignment
  BasisMapper(BasisMapper &&) noexcept;
  BasisMapper &operator=(BasisMapper &&) noexcept;

  /**
   * @brief Map a polynomial from the source context to the target context.
   *
   * @param poly The polynomial to map
   * @return Poly The mapped polynomial in the target context
   * @throws DefaultException if the polynomial doesn't have the correct context
   */
  Poly map(const Poly &poly) const;

  /**
   * @brief Write a PowerBasis polynomial directly into a flattened output
   * buffer laid out as [moduli][degree].
   *
   * This avoids constructing an intermediate Poly when the caller only needs
   * raw coefficient output.
   */
  void write_power_basis_u64(const Poly &poly, uint64_t *out) const;

  // Batch mapping interface for multiple polynomials.
  std::vector<Poly> map_many(const std::vector<Poly> &polys) const;
  // Pointer-based batch mapping to avoid deep copies of Poly.
  std::vector<Poly> map_many(const std::vector<const Poly *> &polys) const;
  void map_many_into(const std::vector<Poly> &polys,
                     std::vector<Poly> &out) const;
  void map_many_into(const std::vector<const Poly *> &polys,
                     std::vector<Poly> &out) const;

  // Equality comparison
  bool operator==(const BasisMapper &other) const;
  bool operator!=(const BasisMapper &other) const;

 private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;

  // Private constructor for PIMPL
  explicit BasisMapper(std::unique_ptr<Impl> impl);
};

}  // namespace bfv::math::rq
#endif  // BASIS_MAPPER_H
