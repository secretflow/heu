#include "math/aux_base_plan.h"

#include "math/aux_base_plan_internal.h"

namespace bfv {
namespace math {

AuxiliaryLiftBackend BuildAuxiliaryLiftBackend(
    const std::shared_ptr<const rq::Context> &base_ctx,
    const std::shared_ptr<const rq::Context> &mul_ctx) {
  AuxiliaryLiftBackend plan;
  internal::PopulateAuxiliaryConverters(plan, base_ctx, mul_ctx);
  internal::PopulateCorrectionChannelPlan(plan, base_ctx);
  return plan;
}

}  // namespace math
}  // namespace bfv
