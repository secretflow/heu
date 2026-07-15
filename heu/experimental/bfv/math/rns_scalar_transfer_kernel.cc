#include "math/rns_transfer_arithmetic.h"
#include "math/rns_transfer_executor.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

TransferWorkset::ScalarTerms BuildScalarCarryTerms(
    const TransferKernelCache &transfer_kernel,
    const ScalingFactor &scaling_factor, const std::vector<uint64_t> &rests) {
  const auto &projection_plan = transfer_kernel.projection_plan;
  const auto &carry_compensation = projection_plan.carry_compensation;
  const auto &carry_window = transfer_kernel.carry_window_plan.carry_window;

  TransferWorkset::ScalarTerms state;
  U256 rounding_accumulator = U256(uint64_t(0));
  for (size_t i = 0; i < rests.size(); ++i) {
    __uint128_t rounding_weight =
        static_cast<__uint128_t>(carry_window.weight_lo[i]) |
        (static_cast<__uint128_t>(carry_window.weight_hi[i]) << 64);
    U256 product = U256(rests[i]) * U256(rounding_weight);
    rounding_accumulator.wrapping_add(product);
  }

  rounding_accumulator >>= (carry_window.shift - 1);
  state.anchor_value = (rounding_accumulator.as_u128() + 1) / 2;

  if (scaling_factor.is_one()) {
    return state;
  }

  U256 compensation_accumulator = U256(uint64_t(0));
  for (size_t i = 0; i < rests.size(); ++i) {
    __uint128_t compensation_weight =
        static_cast<__uint128_t>(carry_compensation.weight_lo[i]) |
        (static_cast<__uint128_t>(carry_compensation.weight_hi[i]) << 64);
    U256 product = U256(rests[i]) * U256(compensation_weight);

    if (carry_compensation.weight_negative[i]) {
      compensation_accumulator.wrapping_sub(product);
    } else {
      compensation_accumulator.wrapping_add(product);
    }
  }

  __uint128_t compensation_bias =
      static_cast<__uint128_t>(carry_compensation.bias_lo) |
      (static_cast<__uint128_t>(carry_compensation.bias_hi) << 64);
  U256 rounded_bias_term = U256(state.anchor_value) * U256(compensation_bias);

  if (carry_compensation.bias_negative) {
    compensation_accumulator.wrapping_add(rounded_bias_term);
  } else {
    compensation_accumulator.wrapping_sub(rounded_bias_term);
  }

  U256 compensation_sign_check = compensation_accumulator >> 255;
  U256 zero = U256(uint64_t(0));
  state.correction_negative = compensation_sign_check > zero;

  if (state.correction_negative) {
    U256 negated = ~compensation_accumulator;
    negated.wrapping_add(U256(uint64_t(1)));
    negated >>= 126;
    state.correction_magnitude = (negated.as_u128() + 1) / 2;
  } else {
    compensation_accumulator >>= 126;
    state.correction_magnitude = (compensation_accumulator.as_u128() + 1) / 2;
  }

  return state;
}

void WriteScalarProjectionRow(const std::shared_ptr<RnsContext> &to_ctx,
                              const TransferKernelCache &transfer_kernel,
                              const ScalingFactor &scaling_factor,
                              const TransferWorkset::ScalarTerms &state,
                              const std::vector<uint64_t> &rests,
                              std::vector<uint64_t> &out,
                              size_t starting_index) {
  const auto &projection_residues =
      transfer_kernel.projection_plan.projection_residues;

  for (size_t i = 0; i < out.size(); ++i) {
    size_t idx = starting_index + i;
    const zq::Modulus &qi = to_ctx->moduli()[idx];

    __uint128_t accumulator =
        static_cast<__uint128_t>(qi.P()) * 2 -
        qi.LazyMulShoup(qi.ReduceU128(state.anchor_value),
                        projection_residues.bias_residues[idx],
                        projection_residues.bias_residues_shoup[idx]);

    if (!scaling_factor.is_one()) {
      uint64_t correction_mod = qi.LazyReduceU128(state.correction_magnitude);
      accumulator +=
          state.correction_negative
              ? (static_cast<__uint128_t>(qi.P()) * 2 - correction_mod)
              : correction_mod;
    }

    const size_t mix_row_start = idx * projection_residues.mix_stride;
    const uint64_t *mix_row = &projection_residues.mix_flat[mix_row_start];
    const uint64_t *mix_row_shoup =
        &projection_residues.mix_shoup_flat[mix_row_start];

    for (size_t j = 0; j < rests.size(); ++j) {
      accumulator += qi.LazyMulShoup(rests[j], mix_row[j], mix_row_shoup[j]);
    }

    out[i] = qi.ReduceU128(accumulator);
  }
}

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv
