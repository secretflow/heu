#ifndef BFV_MATH_RNS_TRANSFER_BACKEND_H
#define BFV_MATH_RNS_TRANSFER_BACKEND_H

#include <memory>
#include <vector>

#include "math/rns_context.h"
#include "math/rns_transfer_plan.h"
#include "math/scaling_factor.h"
#include "util/arena_allocator.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

class ResidueTransferBackend {
 public:
  ResidueTransferBackend(std::shared_ptr<RnsContext> from_ctx,
                         std::shared_ptr<RnsContext> to_ctx,
                         const ScalingFactor &scaling_factor,
                         const TransferKernelCache &transfer_kernel);

  void scale(const std::vector<uint64_t> &rests, std::vector<uint64_t> &out,
             size_t starting_index, ::bfv::util::ArenaHandle pool) const;

  void scale_batch(const std::vector<const uint64_t *> &input_moduli_ptrs,
                   const std::vector<uint64_t *> &output_moduli_ptrs,
                   size_t count, size_t starting_index,
                   ::bfv::util::ArenaHandle pool) const;

 private:
  void scale_decode_bridge(
      const std::vector<const uint64_t *> &input_moduli_ptrs,
      const std::vector<uint64_t *> &output_moduli_ptrs, size_t count,
      ::bfv::util::ArenaHandle pool) const;

  std::shared_ptr<RnsContext> from_;
  std::shared_ptr<RnsContext> to_;
  ScalingFactor scaling_factor_;
  const TransferKernelCache &transfer_kernel_;
};

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv

#endif  // BFV_MATH_RNS_TRANSFER_BACKEND_H
