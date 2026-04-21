#ifndef BFV_MATH_BASIS_TRANSFER_ROUTE_H
#define BFV_MATH_BASIS_TRANSFER_ROUTE_H

#include <memory>
#include <vector>

#include "math/context.h"
#include "math/scaling_factor.h"
#include "util/arena_allocator.h"

namespace bfv::math::rq::internal {

class BasisTransferRoute {
 public:
  BasisTransferRoute(std::shared_ptr<const Context> source_ctx,
                     std::shared_ptr<const Context> target_ctx,
                     const ::bfv::math::rns::ScalingFactor &factor);
  ~BasisTransferRoute();
  BasisTransferRoute(BasisTransferRoute &&) noexcept;
  BasisTransferRoute &operator=(BasisTransferRoute &&) noexcept;

  BasisTransferRoute(const BasisTransferRoute &) = delete;
  BasisTransferRoute &operator=(const BasisTransferRoute &) = delete;

  size_t prefix_passthrough_count() const { return prefix_passthrough_count_; }

  bool has_transfer_backend() const {
    return static_cast<bool>(transfer_backend_);
  }

  bool uses_aux_base_multiply_path() const;

  void scale_batch(const std::vector<const uint64_t *> &input_moduli_ptrs,
                   const std::vector<uint64_t *> &output_moduli_ptrs,
                   size_t count, ::bfv::util::ArenaHandle pool) const;

 private:
  class TransferBackend;
  size_t prefix_passthrough_count_ = 0;
  std::unique_ptr<TransferBackend> transfer_backend_;
};

}  // namespace bfv::math::rq::internal

#endif  // BFV_MATH_BASIS_TRANSFER_ROUTE_H
