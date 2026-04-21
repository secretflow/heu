#ifndef CONTEXT_TRANSFER_H
#define CONTEXT_TRANSFER_H

#include <memory>

#include "math/basis_mapper.h"
#include "math/context.h"
#include "math/poly.h"
#include "math/scaling_factor.h"

namespace bfv::math::rq {

/**
 * @brief Applies a preconfigured polynomial transfer between modulus contexts.
 */
class ContextTransfer {
 public:
  /**
   * @brief Create a context transfer from a context `from` to a context `to`.
   *
   * @param from Source context
   * @param to Target context
   * @return std::unique_ptr<ContextTransfer> The created transfer
   * @throws DefaultException if creation fails
   */
  static std::unique_ptr<ContextTransfer> create(
      std::shared_ptr<const Context> from, std::shared_ptr<const Context> to);

  ~ContextTransfer();

  // Disable copy constructor and assignment
  ContextTransfer(const ContextTransfer &) = delete;
  ContextTransfer &operator=(const ContextTransfer &) = delete;

  // Enable move constructor and assignment
  ContextTransfer(ContextTransfer &&) noexcept;
  ContextTransfer &operator=(ContextTransfer &&) noexcept;

  /**
   * @brief Apply the configured context transfer to a polynomial.
   *
   * @param poly The polynomial to transfer
   * @return Poly The transferred polynomial in the target context
   */
  Poly apply(const Poly &poly) const;

  // Equality comparison
  bool operator==(const ContextTransfer &other) const;
  bool operator!=(const ContextTransfer &other) const;

 private:
  class Impl;
  std::unique_ptr<Impl> pimpl_;

  // Private constructor for PIMPL
  explicit ContextTransfer(std::unique_ptr<Impl> impl);
};

}  // namespace bfv::math::rq
#endif  // CONTEXT_TRANSFER_H
