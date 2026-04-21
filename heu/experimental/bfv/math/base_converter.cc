#include "math/base_converter.h"

#include <algorithm>
#include <stdexcept>

#include "math/base_change_plan.h"

namespace bfv {
namespace math {
namespace rns {

class BaseConverter::Impl {
 public:
  internal::BaseChangePlanData plan;

  explicit Impl(internal::BaseChangePlanData &&plan_data)
      : plan(std::move(plan_data)) {}
};

BaseConverter::BaseConverter(const std::shared_ptr<RnsContext> &ibase,
                             const std::shared_ptr<RnsContext> &obase)
    : ibase_(ibase), obase_(obase) {
  if (!ibase || !obase) {
    throw std::invalid_argument("ibase and obase cannot be null");
  }

  ibase_size_ = ibase->moduli().size();
  obase_size_ = obase->moduli().size();

  if (ibase_size_ == 0 || obase_size_ == 0) {
    throw std::invalid_argument("Empty base not allowed");
  }
  pimpl_ = std::make_unique<Impl>(internal::BuildBaseChangePlan(ibase, obase));
}

BaseConverter::~BaseConverter() = default;

// AVX2 Helper for BaseConverter
#ifdef __AVX2__
#include <immintrin.h>
#endif

void BaseConverter::fast_convert(const uint64_t *in, uint64_t *out) const {
  const auto &q = ibase_->moduli();
  const auto &p = obase_->moduli();
  const uint64_t *input_scale_factors = pimpl_->plan.input_scale_factors;
  const uint64_t *input_scale_hints = pimpl_->plan.input_scale_hints;
  const uint64_t *output_mix_matrix = pimpl_->plan.output_mix_matrix;

  // Step 1: converted_terms[i] = in[i] * inv_punctured_prod[i] mod q[i]
  // Note: Cannot easily vectorize this part as q[i] varies per lane.
  // Unless we use AVX2 gather/scatter or vectorized modular reduction for
  // different moduli. Given ibase_size is usually small (e.g. 4-16), scalar
  // loop with unrolling is okay.
  std::vector<uint64_t> converted_terms(ibase_size_);
  for (size_t i = 0; i < ibase_size_; ++i) {
    converted_terms[i] =
        q[i].MulShoup(in[i], input_scale_factors[i], input_scale_hints[i]);
  }

  // Step 2: out[j] = sum(converted_terms[i] * conversion_row[i]) mod p[j]
  // Vectorize the converted-term dot product against each conversion row.
  // p[j] is constant for the inner loop.
  // converted_terms[i] is shared across j.
  // The conversion rows are stored flat in matrix_flat_.

  for (size_t j = 0; j < obase_size_; ++j) {
    // 128-bit accumulation
    unsigned __int128 acc = 0;
    const uint64_t *conversion_row = output_mix_matrix + j * ibase_size_;

    // Unroll manually
    size_t i = 0;
    for (; i + 3 < ibase_size_; i += 4) {
      acc += (unsigned __int128)converted_terms[i] * conversion_row[i];
      acc += (unsigned __int128)converted_terms[i + 1] * conversion_row[i + 1];
      acc += (unsigned __int128)converted_terms[i + 2] * conversion_row[i + 2];
      acc += (unsigned __int128)converted_terms[i + 3] * conversion_row[i + 3];
    }
    for (; i < ibase_size_; ++i) {
      acc += (unsigned __int128)converted_terms[i] * conversion_row[i];
    }

    out[j] = p[j].ReduceU128(acc);
  }
}

// Helper for AVX2 fused multiply-add of 64-bit integers with 128-bit
// accumulation Since AVX2 doesn't have 64x64->128 multiply-add, we use scalar
// fallback or VPMULUDQ split However, the scalar loop with unrolling on aligned
// memory is often very fast due to compiler auto-vectorization or efficient
// pipelining. But we can explicitly use inline assembly for MULX/ADCX if ADX is
// available, or just rely on __int128. The bottleneck for the array version is
// matrix-vector multiply across 'count' items.

void BaseConverter::fast_convert_array(
    const std::vector<const uint64_t *> &in_ptrs,
    const std::vector<uint64_t *> &out_ptrs, size_t count,
    ArenaHandle pool) const {
  if (in_ptrs.size() != ibase_size_) {
    throw std::invalid_argument("in_ptrs size mismatch");
  }
  if (out_ptrs.size() != obase_size_) {
    throw std::invalid_argument("out_ptrs size mismatch");
  }
  (void)pool;
  fast_convert_array(in_ptrs.data(), out_ptrs.data(), count);
}

void BaseConverter::fast_convert_array(const uint64_t *const *in_ptrs,
                                       uint64_t *const *out_ptrs,
                                       size_t count) const {
  if (count == 0) return;

  const auto &q = ibase_->moduli();
  const auto &p = obase_->moduli();
  const uint64_t *input_scale_factors = pimpl_->plan.input_scale_factors;
  const uint64_t *input_scale_hints = pimpl_->plan.input_scale_hints;
  const uint64_t *output_mix_matrix = pimpl_->plan.output_mix_matrix;

  if (ibase_size_ == 1) {
    const uint64_t *in = in_ptrs[0];
    const auto &qi = q[0];
    const uint64_t punctured_inv = input_scale_factors[0];
    const uint64_t punctured_inv_shoup = input_scale_hints[0];

    for (size_t j = 0; j < obase_size_; ++j) {
      uint64_t *out = out_ptrs[j];
      const auto &pj = p[j];
      for (size_t c = 0; c < count; ++c) {
        uint64_t value = punctured_inv == 1 ? qi.Reduce(in[c])
                                            : qi.MulShoup(in[c], punctured_inv,
                                                          punctured_inv_shoup);
        out[c] = pj.Reduce(value);
      }
    }
    return;
  }

  if (ibase_size_ == 4 && obase_size_ == 1) {
    const auto &q0 = q[0];
    const auto &q1 = q[1];
    const auto &q2 = q[2];
    const auto &q3 = q[3];
    const auto &p0 = p[0];

    const bool inv0_is_one = (input_scale_factors[0] == 1);
    const bool inv1_is_one = (input_scale_factors[1] == 1);
    const bool inv2_is_one = (input_scale_factors[2] == 1);
    const bool inv3_is_one = (input_scale_factors[3] == 1);
    const auto inv0 = q0.PrepareMultiplyOperand(input_scale_factors[0]);
    const auto inv1 = q1.PrepareMultiplyOperand(input_scale_factors[1]);
    const auto inv2 = q2.PrepareMultiplyOperand(input_scale_factors[2]);
    const auto inv3 = q3.PrepareMultiplyOperand(input_scale_factors[3]);

    const uint64_t *in0 = in_ptrs[0];
    const uint64_t *in1 = in_ptrs[1];
    const uint64_t *in2 = in_ptrs[2];
    const uint64_t *in3 = in_ptrs[3];
    uint64_t *out0 = out_ptrs[0];

    const uint64_t m0 = output_mix_matrix[0];
    const uint64_t m1 = output_mix_matrix[1];
    const uint64_t m2 = output_mix_matrix[2];
    const uint64_t m3 = output_mix_matrix[3];
    const bool output0_opt_enabled = p0.SupportsOpt();

    for (size_t c = 0; c < count; ++c) {
      const uint64_t t0 =
          inv0_is_one ? q0.Reduce(in0[c]) : q0.MulOptimized(in0[c], inv0);
      const uint64_t t1 =
          inv1_is_one ? q1.Reduce(in1[c]) : q1.MulOptimized(in1[c], inv1);
      const uint64_t t2 =
          inv2_is_one ? q2.Reduce(in2[c]) : q2.MulOptimized(in2[c], inv2);
      const uint64_t t3 =
          inv3_is_one ? q3.Reduce(in3[c]) : q3.MulOptimized(in3[c], inv3);

      const unsigned __int128 acc = static_cast<unsigned __int128>(t0) * m0 +
                                    static_cast<unsigned __int128>(t1) * m1 +
                                    static_cast<unsigned __int128>(t2) * m2 +
                                    static_cast<unsigned __int128>(t3) * m3;

      out0[c] =
          output0_opt_enabled ? p0.ReduceOptU128(acc) : p0.ReduceU128(acc);
    }
    return;
  }

  if (ibase_size_ == 4) {
    const auto &q0 = q[0];
    const auto &q1 = q[1];
    const auto &q2 = q[2];
    const auto &q3 = q[3];

    const bool inv0_is_one = (input_scale_factors[0] == 1);
    const bool inv1_is_one = (input_scale_factors[1] == 1);
    const bool inv2_is_one = (input_scale_factors[2] == 1);
    const bool inv3_is_one = (input_scale_factors[3] == 1);
    const auto inv0 = q0.PrepareMultiplyOperand(input_scale_factors[0]);
    const auto inv1 = q1.PrepareMultiplyOperand(input_scale_factors[1]);
    const auto inv2 = q2.PrepareMultiplyOperand(input_scale_factors[2]);
    const auto inv3 = q3.PrepareMultiplyOperand(input_scale_factors[3]);

    const uint64_t *in0 = in_ptrs[0];
    const uint64_t *in1 = in_ptrs[1];
    const uint64_t *in2 = in_ptrs[2];
    const uint64_t *in3 = in_ptrs[3];

    thread_local std::vector<uint64_t> converted_term_buffer;
    const size_t required_scratch_words = count * 4;
    if (converted_term_buffer.size() < required_scratch_words) {
      converted_term_buffer.resize(required_scratch_words);
    }
    uint64_t *converted_term_rows = converted_term_buffer.data();

    for (size_t c = 0; c < count; ++c) {
      uint64_t *term_row = converted_term_rows + (c << 2);
      term_row[0] =
          inv0_is_one ? q0.Reduce(in0[c]) : q0.MulOptimized(in0[c], inv0);
      term_row[1] =
          inv1_is_one ? q1.Reduce(in1[c]) : q1.MulOptimized(in1[c], inv1);
      term_row[2] =
          inv2_is_one ? q2.Reduce(in2[c]) : q2.MulOptimized(in2[c], inv2);
      term_row[3] =
          inv3_is_one ? q3.Reduce(in3[c]) : q3.MulOptimized(in3[c], inv3);
    }

    for (size_t j = 0; j < obase_size_; ++j) {
      uint64_t *out = out_ptrs[j];
      const auto &pj = p[j];
      const bool output_mod_opt_enabled = pj.SupportsOpt();
      const uint64_t *conversion_row = output_mix_matrix + (j << 2);
      const uint64_t m0 = conversion_row[0];
      const uint64_t m1 = conversion_row[1];
      const uint64_t m2 = conversion_row[2];
      const uint64_t m3 = conversion_row[3];

      for (size_t c = 0; c < count; ++c) {
        const uint64_t *term_row = converted_term_rows + (c << 2);
        const unsigned __int128 acc =
            static_cast<unsigned __int128>(term_row[0]) * m0 +
            static_cast<unsigned __int128>(term_row[1]) * m1 +
            static_cast<unsigned __int128>(term_row[2]) * m2 +
            static_cast<unsigned __int128>(term_row[3]) * m3;
        out[c] =
            output_mod_opt_enabled ? pj.ReduceOptU128(acc) : pj.ReduceU128(acc);
      }
    }
    return;
  }

  if (ibase_size_ == 4 && obase_size_ == 2) {
    const auto &q0 = q[0];
    const auto &q1 = q[1];
    const auto &q2 = q[2];
    const auto &q3 = q[3];
    const auto &p0 = p[0];
    const auto &p1 = p[1];

    const bool inv0_is_one = (input_scale_factors[0] == 1);
    const bool inv1_is_one = (input_scale_factors[1] == 1);
    const bool inv2_is_one = (input_scale_factors[2] == 1);
    const bool inv3_is_one = (input_scale_factors[3] == 1);
    const auto inv0 = q0.PrepareMultiplyOperand(input_scale_factors[0]);
    const auto inv1 = q1.PrepareMultiplyOperand(input_scale_factors[1]);
    const auto inv2 = q2.PrepareMultiplyOperand(input_scale_factors[2]);
    const auto inv3 = q3.PrepareMultiplyOperand(input_scale_factors[3]);

    const uint64_t *in0 = in_ptrs[0];
    const uint64_t *in1 = in_ptrs[1];
    const uint64_t *in2 = in_ptrs[2];
    const uint64_t *in3 = in_ptrs[3];
    uint64_t *out0 = out_ptrs[0];
    uint64_t *out1 = out_ptrs[1];

    const uint64_t m00 = output_mix_matrix[0];
    const uint64_t m01 = output_mix_matrix[1];
    const uint64_t m02 = output_mix_matrix[2];
    const uint64_t m03 = output_mix_matrix[3];
    const uint64_t m10 = output_mix_matrix[4];
    const uint64_t m11 = output_mix_matrix[5];
    const uint64_t m12 = output_mix_matrix[6];
    const uint64_t m13 = output_mix_matrix[7];
    const bool output0_opt_enabled = p0.SupportsOpt();
    const bool output1_opt_enabled = p1.SupportsOpt();

    for (size_t c = 0; c < count; ++c) {
      const uint64_t term0 =
          inv0_is_one ? q0.Reduce(in0[c]) : q0.MulOptimized(in0[c], inv0);
      const uint64_t term1 =
          inv1_is_one ? q1.Reduce(in1[c]) : q1.MulOptimized(in1[c], inv1);
      const uint64_t term2 =
          inv2_is_one ? q2.Reduce(in2[c]) : q2.MulOptimized(in2[c], inv2);
      const uint64_t term3 =
          inv3_is_one ? q3.Reduce(in3[c]) : q3.MulOptimized(in3[c], inv3);

      const unsigned __int128 acc0 =
          static_cast<unsigned __int128>(term0) * m00 +
          static_cast<unsigned __int128>(term1) * m01 +
          static_cast<unsigned __int128>(term2) * m02 +
          static_cast<unsigned __int128>(term3) * m03;
      const unsigned __int128 acc1 =
          static_cast<unsigned __int128>(term0) * m10 +
          static_cast<unsigned __int128>(term1) * m11 +
          static_cast<unsigned __int128>(term2) * m12 +
          static_cast<unsigned __int128>(term3) * m13;

      out0[c] =
          output0_opt_enabled ? p0.ReduceOptU128(acc0) : p0.ReduceU128(acc0);
      out1[c] =
          output1_opt_enabled ? p1.ReduceOptU128(acc1) : p1.ReduceU128(acc1);
    }
    return;
  }

  // Optimized unrolled loop layout to eliminate scatter array mapping
  // and evaluate condition branches statically outside the loop.
  const size_t max_supported_base_count = 64;
  if (ibase_size_ > max_supported_base_count ||
      obase_size_ > max_supported_base_count) {
    throw std::invalid_argument(
        "ibase_size_ or obase_size_ exceeds internal limit");
  }

  bool output_mod_opt_enabled[64];
  for (size_t j = 0; j < obase_size_; ++j) {
    output_mod_opt_enabled[j] = p[j].SupportsOpt();
  }

  // Evaluate the inv == 1 condition cleanly outside
  bool punctured_inv_is_one[64];
  for (size_t i = 0; i < ibase_size_; ++i) {
    punctured_inv_is_one[i] = (input_scale_factors[i] == 1);
  }

  for (size_t c = 0; c < count; ++c) {
    uint64_t converted_terms[64];
    for (size_t i = 0; i < ibase_size_; ++i) {
      uint64_t val = in_ptrs[i][c];
      converted_terms[i] = punctured_inv_is_one[i]
                               ? q[i].Reduce(val)
                               : q[i].MulShoup(val, input_scale_factors[i],
                                               input_scale_hints[i]);
    }

    for (size_t j = 0; j < obase_size_; ++j) {
      const uint64_t *conversion_row = output_mix_matrix + j * ibase_size_;
      unsigned __int128 acc = 0;

      if (ibase_size_ == 4) {
        acc = (unsigned __int128)converted_terms[0] * conversion_row[0] +
              (unsigned __int128)converted_terms[1] * conversion_row[1] +
              (unsigned __int128)converted_terms[2] * conversion_row[2] +
              (unsigned __int128)converted_terms[3] * conversion_row[3];
      } else if (ibase_size_ == 3) {
        acc = (unsigned __int128)converted_terms[0] * conversion_row[0] +
              (unsigned __int128)converted_terms[1] * conversion_row[1] +
              (unsigned __int128)converted_terms[2] * conversion_row[2];
      } else if (ibase_size_ == 2) {
        acc = (unsigned __int128)converted_terms[0] * conversion_row[0] +
              (unsigned __int128)converted_terms[1] * conversion_row[1];
      } else if (ibase_size_ == 1) {
        acc = (unsigned __int128)converted_terms[0] * conversion_row[0];
      } else {
        for (size_t i = 0; i < ibase_size_; ++i) {
          acc += (unsigned __int128)converted_terms[i] * conversion_row[i];
        }
      }

      out_ptrs[j][c] = output_mod_opt_enabled[j] ? p[j].ReduceOptU128(acc)
                                                 : p[j].ReduceU128(acc);
    }
  }
}

void BaseConverter::fast_convert_array_partial(
    const std::vector<const uint64_t *> &in_ptrs,
    const std::vector<uint64_t *> &out_ptrs, size_t count,
    size_t starting_index, ArenaHandle pool) const {
  if (in_ptrs.size() != ibase_size_) {
    throw std::invalid_argument("in_ptrs size mismatch");
  }
  if (out_ptrs.size() + starting_index > obase_size_) {
    throw std::invalid_argument(
        "out_ptrs size + starting_index exceeds obase_size");
  }
  if (count == 0) return;

  const auto &q = ibase_->moduli();
  const auto &p = obase_->moduli();
  const uint64_t *input_scale_factors = pimpl_->plan.input_scale_factors;
  const uint64_t *output_mix_matrix = pimpl_->plan.output_mix_matrix;
  size_t output_base_count = out_ptrs.size();

  // Reuse thread-local scratch buffer
  thread_local std::vector<uint64_t> partial_scratch_buffer;
  const size_t required_scratch_words = ibase_size_ * count;
  if (partial_scratch_buffer.size() < required_scratch_words) {
    partial_scratch_buffer.resize(required_scratch_words);
  }

  // Step 1: partial_scratch_buffer[i][c] = in[i][c] * inv_punctured_prod[i]
  // mod q[i]
  for (size_t i = 0; i < ibase_size_; ++i) {
    const uint64_t *in_ptr = in_ptrs[i];
    uint64_t *scratch_row = partial_scratch_buffer.data() + i * count;
    q[i].ScalarMulTo(scratch_row, in_ptr, count, input_scale_factors[i]);
  }

  // Step 2: out[j][c] = sum(partial_scratch_buffer[i][c] *
  // conversion_row[i]) mod p[j]
  for (size_t k = 0; k < output_base_count; ++k) {
    for (size_t c = 0; c < count; ++c) {
      size_t j = starting_index + k;
      uint64_t *out_ptr = out_ptrs[k];
      const auto &pj = p[j];
      const uint64_t *conversion_row = output_mix_matrix + j * ibase_size_;

      unsigned __int128 acc = 0;
      for (size_t i = 0; i < ibase_size_; ++i) {
        uint64_t scratch_value = partial_scratch_buffer[i * count + c];
        acc += (unsigned __int128)scratch_value * conversion_row[i];
      }

      out_ptr[c] = pj.ReduceU128(acc);
    }
  }
}

}  // namespace rns
}  // namespace math
}  // namespace bfv
