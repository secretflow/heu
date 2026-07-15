#include "math/rns_transfer_backend.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "math/rns_transfer_executor.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {
namespace {

using Clock = std::chrono::steady_clock;

inline bool heu_dec_profile_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_DEC_PROFILE");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline int64_t micros_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
      .count();
}

}  // namespace

ResidueTransferBackend::ResidueTransferBackend(
    std::shared_ptr<RnsContext> from_ctx, std::shared_ptr<RnsContext> to_ctx,
    const ScalingFactor &scaling_factor,
    const TransferKernelCache &transfer_kernel)
    : from_(std::move(from_ctx)),
      to_(std::move(to_ctx)),
      scaling_factor_(scaling_factor),
      transfer_kernel_(transfer_kernel) {}

void ResidueTransferBackend::scale_decode_bridge(
    const std::vector<const uint64_t *> &input_moduli_ptrs,
    const std::vector<uint64_t *> &output_moduli_ptrs, size_t count,
    ::bfv::util::ArenaHandle pool) const {
  const auto &decode_backend = transfer_kernel_.decode_bridge;
  const auto &dual_channel_context = decode_backend.dual_channel_ctx;
  const auto &q_to_dual_channel = decode_backend.main_to_dual_channel_converter;
  const uint64_t correction_channel_modulus =
      decode_backend.correction_channel_modulus;
  const uint64_t correction_channel_half =
      decode_backend.correction_channel_half;
  const uint64_t primary_channel_modulus =
      decode_backend.primary_channel_modulus;
  const uint64_t inv_correction_channel_mod_primary =
      decode_backend.inv_correction_channel_mod_primary;
  const uint64_t inv_correction_channel_mod_primary_shoup =
      decode_backend.inv_correction_channel_mod_primary_shoup;
  const auto &primary_correction_scale_mod_q =
      decode_backend.primary_correction_scale_mod_q;
  const auto &neg_inv_q_mod_dual_channel =
      decode_backend.neg_inv_q_mod_dual_channel;
  const bool profile = heu_dec_profile_enabled();
  const auto total_begin_time = profile ? Clock::now() : Clock::time_point{};
  int64_t q_multiply_us = 0;
  int64_t dual_channel_convert_us = 0;
  int64_t neg_inv_multiply_us = 0;
  int64_t correction_us = 0;

  const size_t q_modulus_count = from_->moduli_u64().size();
  const size_t dual_channel_count = 2;

  thread_local std::vector<uint64_t> tl_q_scratch_buffer;
  thread_local std::vector<const uint64_t *> tl_q_input_ptr_cache;
  thread_local std::vector<uint64_t *> tl_q_output_ptr_cache;
  if (tl_q_scratch_buffer.size() < q_modulus_count * count) {
    tl_q_scratch_buffer.resize(q_modulus_count * count);
  }
  tl_q_input_ptr_cache.resize(q_modulus_count);
  tl_q_output_ptr_cache.resize(q_modulus_count);
  uint64_t *q_scratch_buffer = tl_q_scratch_buffer.data();
  auto &q_input_modulus_ptrs = tl_q_input_ptr_cache;
  auto &q_scaled_modulus_ptrs = tl_q_output_ptr_cache;

  const auto q_multiply_begin = profile ? Clock::now() : Clock::time_point{};
  for (size_t i = 0; i < q_modulus_count; ++i) {
    q_scaled_modulus_ptrs[i] = q_scratch_buffer + i * count;
    q_input_modulus_ptrs[i] = q_scaled_modulus_ptrs[i];
    from_->moduli()[i].ScalarMulTo(q_scaled_modulus_ptrs[i],
                                   input_moduli_ptrs[i], count,
                                   primary_correction_scale_mod_q[i]);
  }
  if (profile) {
    q_multiply_us = micros_between(q_multiply_begin, Clock::now());
  }

  thread_local std::vector<uint64_t> tl_dual_channel_scratch_buffer;
  thread_local std::vector<uint64_t *> tl_dual_channel_ptr_cache;
  if (tl_dual_channel_scratch_buffer.size() < dual_channel_count * count) {
    tl_dual_channel_scratch_buffer.resize(dual_channel_count * count);
  }
  tl_dual_channel_ptr_cache.resize(dual_channel_count);
  uint64_t *dual_channel_scratch_buffer = tl_dual_channel_scratch_buffer.data();
  auto &dual_channel_ptrs = tl_dual_channel_ptr_cache;
  for (size_t i = 0; i < dual_channel_count; ++i) {
    dual_channel_ptrs[i] = dual_channel_scratch_buffer + i * count;
  }

  const auto dual_channel_convert_begin =
      profile ? Clock::now() : Clock::time_point{};
  q_to_dual_channel->fast_convert_array(q_input_modulus_ptrs, dual_channel_ptrs,
                                        count, pool);
  if (profile) {
    dual_channel_convert_us =
        micros_between(dual_channel_convert_begin, Clock::now());
  }

  const auto neg_inv_multiply_begin =
      profile ? Clock::now() : Clock::time_point{};
  dual_channel_context->moduli()[0].ScalarMulVec(dual_channel_ptrs[0], count,
                                                 neg_inv_q_mod_dual_channel[0]);
  dual_channel_context->moduli()[1].ScalarMulVec(dual_channel_ptrs[1], count,
                                                 neg_inv_q_mod_dual_channel[1]);
  if (profile) {
    neg_inv_multiply_us = micros_between(neg_inv_multiply_begin, Clock::now());
  }

  uint64_t *output_primary_coeffs = output_moduli_ptrs[0];
  uint64_t *primary_input_coeffs = dual_channel_ptrs[0];
  uint64_t *correction_input_coeffs = dual_channel_ptrs[1];
  const auto &primary_ring_modulus = dual_channel_context->moduli()[0];

  const auto correction_stage_begin =
      profile ? Clock::now() : Clock::time_point{};
  for (size_t coeff_index = 0; coeff_index < count; ++coeff_index) {
    uint64_t primary_value = primary_input_coeffs[coeff_index];
    uint64_t correction_value = correction_input_coeffs[coeff_index];

    uint64_t corrected_primary_value;
    if (correction_value > correction_channel_half) {
      uint64_t correction_delta = correction_channel_modulus - correction_value;
      if (correction_delta >= primary_channel_modulus) {
        correction_delta %= primary_channel_modulus;
      }
      corrected_primary_value =
          primary_ring_modulus.Add(primary_value, correction_delta);
    } else {
      uint64_t correction_delta = correction_value;
      if (correction_delta >= primary_channel_modulus) {
        correction_delta %= primary_channel_modulus;
      }
      corrected_primary_value =
          primary_ring_modulus.Sub(primary_value, correction_delta);
    }

    output_primary_coeffs[coeff_index] = primary_ring_modulus.MulShoup(
        corrected_primary_value, inv_correction_channel_mod_primary,
        inv_correction_channel_mod_primary_shoup);
  }
  if (profile) {
    correction_us = micros_between(correction_stage_begin, Clock::now());
    const auto total_us = micros_between(total_begin_time, Clock::now());
    std::cerr << "[HEU_DEC_SCALE_PROFILE]"
              << " count=" << count << " q_multiply_us=" << q_multiply_us
              << " conv_bridge_us=" << dual_channel_convert_us
              << " mul_neg_inv_us=" << neg_inv_multiply_us
              << " corr_us=" << correction_us << " total_us=" << total_us
              << '\n';
  }
}

void ResidueTransferBackend::scale(const std::vector<uint64_t> &rests,
                                   std::vector<uint64_t> &out,
                                   size_t starting_index,
                                   ::bfv::util::ArenaHandle pool) const {
  const auto &decode_backend = transfer_kernel_.decode_bridge;
  assert(rests.size() == from_->moduli_u64().size());
  assert(!out.empty());
  assert(starting_index + out.size() <= to_->moduli_u64().size());

  if (decode_backend.enabled) {
    assert(out.size() == 1);
    std::vector<const uint64_t *> in_ptrs(rests.size());
    for (size_t i = 0; i < rests.size(); ++i) {
      in_ptrs[i] = &rests[i];
    }
    std::vector<uint64_t *> out_ptrs(1);
    out_ptrs[0] = out.data();
    scale_decode_bridge(in_ptrs, out_ptrs, 1, pool);
    return;
  }

  auto state = BuildScalarCarryTerms(transfer_kernel_, scaling_factor_, rests);
  WriteScalarProjectionRow(to_, transfer_kernel_, scaling_factor_, state, rests,
                           out, starting_index);
}

void ResidueTransferBackend::scale_batch(
    const std::vector<const uint64_t *> &input_moduli_ptrs,
    const std::vector<uint64_t *> &output_moduli_ptrs, size_t count,
    size_t starting_index, ::bfv::util::ArenaHandle pool) const {
  const auto &decode_backend = transfer_kernel_.decode_bridge;
  const size_t from_size = from_->moduli_u64().size();

  if (input_moduli_ptrs.size() != from_size) {
    throw std::invalid_argument("Input moduli ptrs count mismatch");
  }

  if (decode_backend.enabled) {
    scale_decode_bridge(input_moduli_ptrs, output_moduli_ptrs, count, pool);
    return;
  }

  auto scratch =
      BuildBatchCarryWorkset(from_, transfer_kernel_, scaling_factor_,
                             input_moduli_ptrs, output_moduli_ptrs, pool);
  if (scaling_factor_.is_one()) {
    WriteBatchProjectionWithoutCompensation(to_, transfer_kernel_, scratch,
                                            count, starting_index);
    return;
  }
  WriteBatchProjectionWithCompensation(to_, transfer_kernel_, scaling_factor_,
                                       scratch, count, starting_index);
}

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv
