#include <algorithm>

#include "math/rns_transfer_arithmetic.h"
#include "math/rns_transfer_executor.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

TransferWorkset::BatchWorkset BuildBatchCarryWorkset(
    const std::shared_ptr<RnsContext> &from_ctx,
    const TransferKernelCache &transfer_kernel,
    const ScalingFactor &scaling_factor,
    const std::vector<const uint64_t *> &input_moduli_ptrs,
    const std::vector<uint64_t *> &output_moduli_ptrs, ArenaHandle pool) {
  const auto &projection_plan = transfer_kernel.projection_plan;
  const auto &carry_compensation = projection_plan.carry_compensation;
  const auto &carry_window = transfer_kernel.carry_window_plan.carry_window;

  TransferWorkset::BatchWorkset scratch;
  const size_t from_size = from_ctx->moduli_u64().size();
  const size_t to_size = output_moduli_ptrs.size();

  scratch.const_words = pool.allocate<uint64_t>(from_size * 5);
  scratch.round_lo = scratch.const_words.get();
  scratch.round_hi = scratch.round_lo + from_size;
  scratch.comp_lo = scratch.round_hi + from_size;
  scratch.comp_hi = scratch.comp_lo + from_size;
  scratch.sign_words = pool.allocate<uint8_t>(from_size);
  scratch.comp_negative = scratch.sign_words.get();

  bool needs_compensation = !scaling_factor.is_one();
  for (size_t k = 0; k < from_size; ++k) {
    scratch.round_lo[k] = carry_window.weight_lo[k];
    scratch.round_hi[k] = carry_window.weight_hi[k];
    if (needs_compensation) {
      scratch.comp_lo[k] = carry_compensation.weight_lo[k];
      scratch.comp_hi[k] = carry_compensation.weight_hi[k];
      scratch.comp_negative[k] = carry_compensation.weight_negative[k] ? 1 : 0;
    }
  }

  scratch.rounding_shift = carry_window.shift - 1;
  scratch.bias_lo = carry_compensation.bias_lo;
  scratch.bias_hi = carry_compensation.bias_hi;
  scratch.bias_negative = carry_compensation.bias_negative;
  scratch.safe_from_size = std::min(from_size, scratch.input_ptrs.size());
  scratch.safe_to_size = std::min(to_size, scratch.output_ptrs.size());

  for (size_t k = 0; k < scratch.safe_from_size; ++k) {
    scratch.input_ptrs[k] = input_moduli_ptrs[k];
  }
  for (size_t k = 0; k < scratch.safe_to_size; ++k) {
    scratch.output_ptrs[k] = output_moduli_ptrs[k];
  }

  return scratch;
}

void WriteBatchProjectionWithoutCompensation(
    const std::shared_ptr<RnsContext> &to_ctx,
    const TransferKernelCache &transfer_kernel,
    const TransferWorkset::BatchWorkset &scratch, size_t count,
    size_t starting_index) {
  const auto &projection_residues =
      transfer_kernel.projection_plan.projection_residues;
  const size_t TILE_SIZE = 512;

  for (size_t c_start = 0; c_start < count; c_start += TILE_SIZE) {
    size_t c_end = std::min(c_start + TILE_SIZE, count);
    size_t tile_len = c_end - c_start;
    __uint128_t rounded_cache[TILE_SIZE];

    size_t i = 0;
    for (; i + 4 <= tile_len; i += 4) {
      size_t c0 = c_start + i;
      size_t c1 = c0 + 1;
      size_t c2 = c0 + 2;
      size_t c3 = c0 + 3;

      unsigned __int128 v_acc0_0 = 0, v_acc1_0 = 0, v_acc2_0 = 0;
      unsigned __int128 v_acc0_1 = 0, v_acc1_1 = 0, v_acc2_1 = 0;
      unsigned __int128 v_acc0_2 = 0, v_acc1_2 = 0, v_acc2_2 = 0;
      unsigned __int128 v_acc0_3 = 0, v_acc1_3 = 0, v_acc2_3 = 0;

      for (size_t k = 0; k < scratch.safe_from_size; ++k) {
        uint64_t g_lo = scratch.round_lo[k];
        uint64_t g_hi = scratch.round_hi[k];

        auto acc_step = [&](uint64_t val, unsigned __int128 &a0,
                            unsigned __int128 &a1, unsigned __int128 &a2) {
          unsigned __int128 pl = (unsigned __int128)val * g_lo;
          unsigned __int128 ph = (unsigned __int128)val * g_hi;
          a0 += (uint64_t)pl;
          a1 += (uint64_t)(pl >> 64);
          a1 += (uint64_t)ph;
          a2 += (uint64_t)(ph >> 64);
        };
        acc_step(scratch.input_ptrs[k][c0], v_acc0_0, v_acc1_0, v_acc2_0);
        acc_step(scratch.input_ptrs[k][c1], v_acc0_1, v_acc1_1, v_acc2_1);
        acc_step(scratch.input_ptrs[k][c2], v_acc0_2, v_acc1_2, v_acc2_2);
        acc_step(scratch.input_ptrs[k][c3], v_acc0_3, v_acc1_3, v_acc2_3);
      }

      auto finalize = [&](unsigned __int128 &a0, unsigned __int128 &a1,
                          unsigned __int128 &a2, __uint128_t &out) {
        a1 += (a0 >> 64);
        a2 += (a1 >> 64);
        U256 vx;
        vx.words[0] = (uint64_t)a0;
        vx.words[1] = (uint64_t)a1;
        vx.words[2] = (uint64_t)a2;
        vx.words[3] = (uint64_t)(a2 >> 64);
        vx >>= scratch.rounding_shift;
        out = (vx.as_u128() + 1) / 2;
      };
      finalize(v_acc0_0, v_acc1_0, v_acc2_0, rounded_cache[i]);
      finalize(v_acc0_1, v_acc1_1, v_acc2_1, rounded_cache[i + 1]);
      finalize(v_acc0_2, v_acc1_2, v_acc2_2, rounded_cache[i + 2]);
      finalize(v_acc0_3, v_acc1_3, v_acc2_3, rounded_cache[i + 3]);
    }

    for (; i < tile_len; ++i) {
      size_t c = c_start + i;
      unsigned __int128 v_acc0 = 0, v_acc1 = 0, v_acc2 = 0;
      for (size_t k = 0; k < scratch.safe_from_size; ++k) {
        uint64_t val = scratch.input_ptrs[k][c];
        unsigned __int128 pl = (unsigned __int128)val * scratch.round_lo[k];
        unsigned __int128 ph = (unsigned __int128)val * scratch.round_hi[k];
        v_acc0 += (uint64_t)pl;
        v_acc1 += (uint64_t)(pl >> 64);
        v_acc1 += (uint64_t)ph;
        v_acc2 += (uint64_t)(ph >> 64);
      }
      v_acc1 += (v_acc0 >> 64);
      v_acc2 += (v_acc1 >> 64);
      U256 vx;
      vx.words[0] = (uint64_t)v_acc0;
      vx.words[1] = (uint64_t)v_acc1;
      vx.words[2] = (uint64_t)v_acc2;
      vx.words[3] = (uint64_t)(v_acc2 >> 64);
      vx >>= scratch.rounding_shift;
      rounded_cache[i] = (vx.as_u128() + 1) / 2;
    }

    for (size_t j = 0; j < scratch.safe_to_size; ++j) {
      size_t mod_idx = starting_index + j;
      const auto &qi = to_ctx->moduli()[mod_idx];
      uint64_t *out_ptr = scratch.output_ptrs[j] + c_start;

      auto barrett = qi.GetBarrettConstants();
      uint64_t p = barrett.value;
      uint64_t bias_residue = projection_residues.bias_residues[mod_idx];
      uint64_t bias_residue_shoup =
          projection_residues.bias_residues_shoup[mod_idx];
      unsigned __int128 P2 = (unsigned __int128)p << 1;
      const uint64_t *mix_row = projection_residues.mix_flat.data() +
                                mod_idx * projection_residues.mix_stride;

      for (size_t idx = 0; idx < tile_len; ++idx) {
        size_t c = c_start + idx;
        uint64_t rounded_mod = qi.ReduceU128(rounded_cache[idx]);
        uint64_t bias_term = transfer_lazy_mul_shoup(rounded_mod, bias_residue,
                                                     bias_residue_shoup, p);
        unsigned __int128 accumulator = P2 - bias_term;
        for (size_t k = 0; k < scratch.safe_from_size; ++k) {
          accumulator +=
              (unsigned __int128)scratch.input_ptrs[k][c] * mix_row[k];
        }
        out_ptr[idx] = transfer_reduce_u128(accumulator, barrett);
      }
    }
  }
}

void WriteBatchProjectionWithCompensation(
    const std::shared_ptr<RnsContext> &to_ctx,
    const TransferKernelCache &transfer_kernel,
    const ScalingFactor &scaling_factor,
    const TransferWorkset::BatchWorkset &scratch, size_t count,
    size_t starting_index) {
  (void)scaling_factor;
  const auto &projection_residues =
      transfer_kernel.projection_plan.projection_residues;
  const size_t TILE_SIZE = 512;

  for (size_t c_start = 0; c_start < count; c_start += TILE_SIZE) {
    size_t c_end = std::min(c_start + TILE_SIZE, count);
    size_t tile_len = c_end - c_start;

    __uint128_t rounded_cache[TILE_SIZE];
    __uint128_t compensation_cache[TILE_SIZE];
    bool correction_negative_cache[TILE_SIZE];

    for (size_t i = 0; i < tile_len; ++i) {
      size_t c = c_start + i;

      unsigned __int128 v_acc0 = 0, v_acc1 = 0, v_acc2 = 0;
      unsigned __int128 wp_acc0 = 0, wp_acc1 = 0, wp_acc2 = 0;
      unsigned __int128 wn_acc0 = 0, wn_acc1 = 0, wn_acc2 = 0;

      for (size_t k = 0; k < scratch.safe_from_size; ++k) {
        uint64_t val = scratch.input_ptrs[k][c];

        unsigned __int128 pl = (unsigned __int128)val * scratch.round_lo[k];
        unsigned __int128 ph = (unsigned __int128)val * scratch.round_hi[k];
        v_acc0 += (uint64_t)pl;
        v_acc1 += (uint64_t)(pl >> 64);
        v_acc1 += (uint64_t)ph;
        v_acc2 += (uint64_t)(ph >> 64);

        unsigned __int128 wl = (unsigned __int128)val * scratch.comp_lo[k];
        unsigned __int128 wh = (unsigned __int128)val * scratch.comp_hi[k];
        if (scratch.comp_negative[k]) {
          wn_acc0 += (uint64_t)wl;
          wn_acc1 += (uint64_t)(wl >> 64);
          wn_acc1 += (uint64_t)wh;
          wn_acc2 += (uint64_t)(wh >> 64);
        } else {
          wp_acc0 += (uint64_t)wl;
          wp_acc1 += (uint64_t)(wl >> 64);
          wp_acc1 += (uint64_t)wh;
          wp_acc2 += (uint64_t)(wh >> 64);
        }
      }

      v_acc1 += (v_acc0 >> 64);
      v_acc2 += (v_acc1 >> 64);
      U256 vx;
      vx.words[0] = (uint64_t)v_acc0;
      vx.words[1] = (uint64_t)v_acc1;
      vx.words[2] = (uint64_t)v_acc2;
      vx.words[3] = (uint64_t)(v_acc2 >> 64);
      vx >>= scratch.rounding_shift;
      rounded_cache[i] = (vx.as_u128() + 1) / 2;

      wp_acc1 += (wp_acc0 >> 64);
      wp_acc2 += (wp_acc1 >> 64);
      wn_acc1 += (wn_acc0 >> 64);
      wn_acc2 += (wn_acc1 >> 64);

      U256 wp;
      wp.words[0] = (uint64_t)wp_acc0;
      wp.words[1] = (uint64_t)wp_acc1;
      wp.words[2] = (uint64_t)wp_acc2;
      wp.words[3] = (uint64_t)(wp_acc2 >> 64);
      U256 wn;
      wn.words[0] = (uint64_t)wn_acc0;
      wn.words[1] = (uint64_t)wn_acc1;
      wn.words[2] = (uint64_t)wn_acc2;
      wn.words[3] = (uint64_t)(wn_acc2 >> 64);

      U256 compensation_accumulator = wp;
      compensation_accumulator.wrapping_sub(wn);

      __uint128_t compensation_bias =
          static_cast<__uint128_t>(scratch.bias_lo) |
          (static_cast<__uint128_t>(scratch.bias_hi) << 64);
      U256 bias_term = U256(rounded_cache[i]) * U256(compensation_bias);

      if (scratch.bias_negative) {
        compensation_accumulator.wrapping_add(bias_term);
      } else {
        compensation_accumulator.wrapping_sub(bias_term);
      }

      U256 compensation_sign_check = compensation_accumulator >> 255;
      U256 zero = U256(uint64_t(0));
      bool correction_negative_local = compensation_sign_check > zero;
      if (correction_negative_local) {
        U256 n = ~compensation_accumulator;
        n.wrapping_add(U256(uint64_t(1)));
        n >>= 126;
        compensation_cache[i] = (n.as_u128() + 1) / 2;
        correction_negative_cache[i] = true;
      } else {
        compensation_accumulator >>= 126;
        compensation_cache[i] = (compensation_accumulator.as_u128() + 1) / 2;
        correction_negative_cache[i] = false;
      }
    }

    for (size_t j = 0; j < scratch.safe_to_size; ++j) {
      size_t mod_idx = starting_index + j;
      const auto &qi = to_ctx->moduli()[mod_idx];
      uint64_t *out_ptr = scratch.output_ptrs[j] + c_start;

      auto barrett = qi.GetBarrettConstants();
      uint64_t p = barrett.value;
      uint64_t bias_residue = projection_residues.bias_residues[mod_idx];
      uint64_t bias_residue_shoup =
          projection_residues.bias_residues_shoup[mod_idx];
      unsigned __int128 P2 = (unsigned __int128)p << 1;
      const uint64_t *mix_row = projection_residues.mix_flat.data() +
                                mod_idx * projection_residues.mix_stride;

      for (size_t idx = 0; idx < tile_len; ++idx) {
        size_t c = c_start + idx;
        uint64_t compensation_mod = qi.LazyReduceU128(compensation_cache[idx]);
        uint64_t rounded_mod = qi.ReduceU128(rounded_cache[idx]);
        uint64_t bias_term = transfer_lazy_mul_shoup(rounded_mod, bias_residue,
                                                     bias_residue_shoup, p);
        unsigned __int128 accumulator = P2 - bias_term;
        accumulator += correction_negative_cache[idx] ? (P2 - compensation_mod)
                                                      : compensation_mod;

        for (size_t k = 0; k < scratch.safe_from_size; ++k) {
          accumulator +=
              (unsigned __int128)scratch.input_ptrs[k][c] * mix_row[k];
        }
        out_ptr[idx] = transfer_reduce_u128(accumulator, barrett);
      }
    }
  }
}

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv
