#ifndef RNS_TRANSFER_PLAN_H
#define RNS_TRANSFER_PLAN_H

#include <array>
#include <cstdint>
#include <memory>
#include <tuple>
#include <vector>

#include "math/base_converter.h"
#include "math/biguint.h"
#include "math/rns_context.h"
#include "math/scaling_factor.h"
#include "util/arena_allocator.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

struct TransferKernelCache {
  struct ProjectionResidueCache {
    alignas(64) std::vector<uint64_t> bias_residues;
    alignas(64) std::vector<uint64_t> bias_residues_shoup;
    alignas(64) std::vector<uint64_t> mix_flat;
    alignas(64) std::vector<uint64_t> mix_shoup_flat;
    size_t mix_stride = 0;
  };

  struct CarryCompensationCache {
    uint64_t bias_lo = 0;
    uint64_t bias_hi = 0;
    bool bias_negative = false;
    alignas(64) std::vector<uint64_t> weight_lo;
    alignas(64) std::vector<uint64_t> weight_hi;
    alignas(64) std::vector<bool> weight_negative;
  };

  struct CarryWindowCache {
    alignas(64) std::vector<uint64_t> weight_lo;
    alignas(64) std::vector<uint64_t> weight_hi;
    size_t shift = 0;
  };

  struct DecodeBridgeBackend {
    std::shared_ptr<RnsContext> dual_channel_ctx;
    std::unique_ptr<BaseConverter> main_to_dual_channel_converter;
    uint64_t correction_channel_modulus = 0;
    uint64_t correction_channel_half = 0;
    uint64_t primary_channel_modulus = 0;
    uint64_t inv_correction_channel_mod_primary = 0;
    uint64_t inv_correction_channel_mod_primary_shoup = 0;
    std::vector<uint64_t> primary_correction_scale_mod_q;
    std::vector<uint64_t> neg_inv_q_mod_dual_channel;
    bool enabled = false;
  };

  struct ProjectionPlan {
    ProjectionResidueCache projection_residues;
    CarryCompensationCache carry_compensation;
  };

  struct CarryWindowPlan {
    CarryWindowCache carry_window;
  };

  ProjectionPlan projection_plan;
  CarryWindowPlan carry_window_plan;
  DecodeBridgeBackend decode_bridge;
};

struct TransferWorkset {
  struct ScalarTerms {
    __uint128_t anchor_value = 0;
    bool correction_negative = false;
    __uint128_t correction_magnitude = 0;
  };

  struct BatchWorkset {
    ::bfv::util::Pointer<uint64_t> const_words;
    ::bfv::util::Pointer<uint8_t> sign_words;
    uint64_t *round_lo = nullptr;
    uint64_t *round_hi = nullptr;
    uint64_t *comp_lo = nullptr;
    uint64_t *comp_hi = nullptr;
    uint8_t *comp_negative = nullptr;
    size_t rounding_shift = 0;
    uint64_t bias_lo = 0;
    uint64_t bias_hi = 0;
    bool bias_negative = false;
    size_t safe_from_size = 0;
    size_t safe_to_size = 0;
    std::array<const uint64_t *, 32> input_ptrs{};
    std::array<uint64_t *, 32> output_ptrs{};
  };
};

void PopulateOutputBiasProjection(
    const std::shared_ptr<RnsContext> &from_ctx,
    const std::shared_ptr<RnsContext> &to_ctx, const ScalingFactor &factor,
    TransferKernelCache::ProjectionResidueCache &projection_residues,
    TransferKernelCache::CarryCompensationCache &carry_compensation);

void PopulateCrossBasisMixProjection(
    const std::shared_ptr<RnsContext> &from_ctx,
    const std::shared_ptr<RnsContext> &to_ctx, const ScalingFactor &factor,
    TransferKernelCache::ProjectionResidueCache &projection_residues,
    TransferKernelCache::CarryCompensationCache &carry_compensation);

TransferKernelCache::ProjectionPlan BuildTransferProjectionPlan(
    const std::shared_ptr<RnsContext> &from_ctx,
    const std::shared_ptr<RnsContext> &to_ctx, const ScalingFactor &factor);

TransferKernelCache::CarryWindowPlan BuildCarryWindowPlan(
    const std::shared_ptr<RnsContext> &from_ctx);

TransferKernelCache::DecodeBridgeBackend BuildDecodeBridgeBackend(
    const std::shared_ptr<RnsContext> &from_ctx,
    const std::shared_ptr<RnsContext> &to_ctx);

std::tuple<std::vector<uint64_t>, uint64_t, uint64_t, bool>
DeriveProjectionSample(const RnsContext &ctx, const BigUint &input,
                       const BigUint &numerator, const BigUint &denominator,
                       bool round_up);

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv

#endif
