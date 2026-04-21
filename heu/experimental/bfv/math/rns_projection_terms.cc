#include <tuple>
#include <utility>
#include <vector>

#include "math/rns_transfer_plan.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

std::tuple<std::vector<uint64_t>, uint64_t, uint64_t, bool>
DeriveProjectionSample(const RnsContext &ctx, const BigUint &input,
                       const BigUint &numerator, const BigUint &denominator,
                       bool round_up) {
  BigUint rounded_input =
      (numerator * input + (denominator >> 1)) / denominator;
  auto projected_residues = ctx.project(rounded_input);
  BigUint carry_term = (numerator * input) % denominator;
  bool carry_negative = false;
  if (denominator > BigUint::one()) {
    if (denominator % BigUint(2) == BigUint(1)) {
      if (carry_term > (denominator >> 1)) {
        carry_negative = true;
        carry_term = denominator - carry_term;
      }
    } else {
      if (carry_term >= (denominator >> 1)) {
        carry_negative = true;
        carry_term = denominator - carry_term;
      }
    }
  }
  if (round_up) {
    if (carry_negative) {
      carry_term = (carry_term << 127) / denominator;
    } else {
      carry_term =
          ((carry_term << 127) + denominator - BigUint::one()) / denominator;
    }
  } else {
    if (carry_negative) {
      carry_term =
          ((carry_term << 127) + denominator - BigUint::one()) / denominator;
    } else {
      carry_term = (carry_term << 127) / denominator;
    }
  }

  BigUint carry_hi = carry_term >> 64;
  carry_term -= carry_hi << 64;
  uint64_t carry_lo = carry_term.to_u64();
  uint64_t carry_hi_u64 = carry_hi.to_u64();
  return {projected_residues, carry_lo, carry_hi_u64, carry_negative};
}

void PopulateOutputBiasProjection(
    const std::shared_ptr<RnsContext> &from_ctx,
    const std::shared_ptr<RnsContext> &to_ctx, const ScalingFactor &factor,
    TransferKernelCache::ProjectionResidueCache &projection_residues,
    TransferKernelCache::CarryCompensationCache &carry_compensation) {
  auto [projected_anchor, carry_lo, carry_hi, carry_negative] =
      DeriveProjectionSample(*to_ctx, from_ctx->modulus(), factor.numerator(),
                             factor.denominator(), false);
  projection_residues.bias_residues = std::move(projected_anchor);
  carry_compensation.bias_lo = carry_lo;
  carry_compensation.bias_hi = carry_hi;
  carry_compensation.bias_negative = carry_negative;
  projection_residues.bias_residues_shoup.resize(
      projection_residues.bias_residues.size());
  for (size_t i = 0; i < projection_residues.bias_residues.size(); ++i) {
    projection_residues.bias_residues_shoup[i] =
        to_ctx->moduli()[i].Shoup(projection_residues.bias_residues[i]);
  }
}

void PopulateCrossBasisMixProjection(
    const std::shared_ptr<RnsContext> &from_ctx,
    const std::shared_ptr<RnsContext> &to_ctx, const ScalingFactor &factor,
    TransferKernelCache::ProjectionResidueCache &projection_residues,
    TransferKernelCache::CarryCompensationCache &carry_compensation) {
  const size_t to_size = to_ctx->moduli_u64().size();
  const size_t from_size = from_ctx->moduli_u64().size();
  projection_residues.mix_stride = from_size;
  projection_residues.mix_flat.resize(to_size * from_size, 0);
  projection_residues.mix_shoup_flat.resize(to_size * from_size, 0);

  carry_compensation.weight_lo.resize(from_ctx->garner().size());
  carry_compensation.weight_hi.resize(from_ctx->garner().size());
  carry_compensation.weight_negative.resize(from_ctx->garner().size());
  for (size_t i = 0; i < from_ctx->garner().size(); ++i) {
    auto [mix_projection_row, row_carry_lo, row_carry_hi, row_carry_negative] =
        DeriveProjectionSample(*to_ctx, from_ctx->get_garner(i),
                               factor.numerator(), factor.denominator(), false);
    for (size_t j = 0; j < to_size; ++j) {
      const size_t flat_idx = j * projection_residues.mix_stride + i;
      projection_residues.mix_flat[flat_idx] =
          to_ctx->moduli()[j].Reduce(mix_projection_row[j]);
      projection_residues.mix_shoup_flat[flat_idx] =
          to_ctx->moduli()[j].Shoup(projection_residues.mix_flat[flat_idx]);
    }
    carry_compensation.weight_lo[i] = row_carry_lo;
    carry_compensation.weight_hi[i] = row_carry_hi;
    carry_compensation.weight_negative[i] = row_carry_negative;
  }
}

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv
