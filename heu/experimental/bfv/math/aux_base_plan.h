#ifndef BFV_MATH_AUX_BASE_PLAN_H
#define BFV_MATH_AUX_BASE_PLAN_H

#include <memory>

#include "math/aux_base_extender.h"

namespace bfv {
namespace math {

AuxiliaryLiftBackend BuildAuxiliaryLiftBackend(
    const std::shared_ptr<const rq::Context> &base_ctx,
    const std::shared_ptr<const rq::Context> &mul_ctx);

}  // namespace math
}  // namespace bfv

#endif  // BFV_MATH_AUX_BASE_PLAN_H
