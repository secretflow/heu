#include "math/rns_transfer_plan.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

TransferKernelCache::ProjectionPlan BuildTransferProjectionPlan(
    const std::shared_ptr<RnsContext> &from_ctx,
    const std::shared_ptr<RnsContext> &to_ctx, const ScalingFactor &factor) {
  TransferKernelCache::ProjectionPlan projection_plan;
  PopulateOutputBiasProjection(from_ctx, to_ctx, factor,
                               projection_plan.projection_residues,
                               projection_plan.carry_compensation);
  PopulateCrossBasisMixProjection(from_ctx, to_ctx, factor,
                                  projection_plan.projection_residues,
                                  projection_plan.carry_compensation);
  return projection_plan;
}

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv
