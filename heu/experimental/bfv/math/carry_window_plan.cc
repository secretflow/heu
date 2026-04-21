#include <limits>

#include "math/rns_transfer_plan.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

TransferKernelCache::CarryWindowPlan BuildCarryWindowPlan(
    const std::shared_ptr<RnsContext> &from_ctx) {
  TransferKernelCache::CarryWindowPlan carry_window_plan;
  auto &carry_window = carry_window_plan.carry_window;
  auto ilog2_u128 = [](unsigned __int128 x) -> int {
    int r = -1;
    while (x > 0) {
      x >>= 1;
      r++;
    }
    return r;
  };
  auto next_power_of_two = [&](unsigned __int128 x) -> unsigned __int128 {
    if (x == 0) return 1;
    int l = ilog2_u128(x - 1) + 1;
    return (unsigned __int128)1 << l;
  };

  int min_shift = std::numeric_limits<int>::max();
  const size_t modulus_count = from_ctx->moduli_u64().size();
  for (auto qi : from_ctx->moduli_u64()) {
    unsigned __int128 product =
        (unsigned __int128)qi * (unsigned __int128)modulus_count;
    unsigned __int128 npot = next_power_of_two(product);
    int log_val = ilog2_u128(npot);
    int shift_val = 192 - 1 - log_val;
    if (shift_val < min_shift) min_shift = shift_val;
  }
  carry_window.shift = std::min(min_shift, 127);

  carry_window.weight_lo.resize(from_ctx->garner().size());
  carry_window.weight_hi.resize(from_ctx->garner().size());
  for (size_t i = 0; i < from_ctx->garner().size(); ++i) {
    BigUint rounded_weight = ((from_ctx->get_garner(i) << carry_window.shift) +
                              (from_ctx->modulus() >> 1)) /
                             from_ctx->modulus();
    BigUint rounded_weight_hi = rounded_weight >> 64;
    rounded_weight -= rounded_weight_hi << 64;
    carry_window.weight_lo[i] = rounded_weight.to_u64();
    carry_window.weight_hi[i] = rounded_weight_hi.to_u64();
  }
  return carry_window_plan;
}

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv
