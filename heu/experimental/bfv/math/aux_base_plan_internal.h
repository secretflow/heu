#ifndef BFV_MATH_AUX_BASE_PLAN_INTERNAL_H
#define BFV_MATH_AUX_BASE_PLAN_INTERNAL_H

#include <memory>

#include "math/aux_base_plan.h"

namespace bfv {
namespace math {
namespace internal {

void PopulateAuxiliaryConverters(
    AuxiliaryLiftBackend &plan,
    const std::shared_ptr<const rq::Context> &base_ctx,
    const std::shared_ptr<const rq::Context> &mul_ctx);

void PopulateCorrectionChannelPlan(
    AuxiliaryLiftBackend &plan,
    const std::shared_ptr<const rq::Context> &base_ctx);

}  // namespace internal
}  // namespace math
}  // namespace bfv

#endif  // BFV_MATH_AUX_BASE_PLAN_INTERNAL_H
