#include "math/aux_base_extender.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include "math/ntt_harvey.h"

namespace bfv {
namespace math {
using namespace rq;

namespace {
using Clock = std::chrono::steady_clock;

inline bool heu_lift_profile_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_LIFT_PROFILE");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline int64_t micros_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
      .count();
}

inline bool heu_batch_ntt_enabled() {
  static const bool enabled = [] {
    const char *disable_env = std::getenv("HEU_BFV_DISABLE_BATCH_NTT");
    if (disable_env && disable_env[0] != '\0' && disable_env[0] != '0') {
      return false;
    }
    const char *enable_env = std::getenv("HEU_BFV_ENABLE_BATCH_NTT");
    if (enable_env && enable_env[0] != '\0' && enable_env[0] != '0') {
      return true;
    }
    return false;
  }();
  return enabled;
}

inline bool heu_batch_q_ntt4_enabled() {
  static const bool enabled = [] {
    const char *disable_env = std::getenv("HEU_BFV_DISABLE_BATCH_Q_NTT4");
    if (disable_env && disable_env[0] != '\0' && disable_env[0] != '0') {
      return false;
    }
    const char *enable_env = std::getenv("HEU_BFV_ENABLE_BATCH_Q_NTT4");
    return enable_env && enable_env[0] != '\0' && enable_env[0] != '0';
  }();
  return enabled;
}

inline uint64_t mul_mod_2k(uint64_t lhs, uint64_t rhs, uint64_t mask) {
  return (lhs * rhs) & mask;
}

inline void inverse_ntt_lazy_to_power_inplace(Poly &poly) {
  if (poly.representation() == ::bfv::math::Representation::PowerBasis) {
    return;
  }
  if (poly.representation() == ::bfv::math::Representation::NttShoup) {
    poly.change_representation(::bfv::math::Representation::Ntt);
  }
  if (poly.representation() != ::bfv::math::Representation::Ntt) {
    throw std::runtime_error(
        "Aux-base lazy inverse NTT expects Ntt representation");
  }

  const auto &ctx = poly.ctx();
  const auto &ops = ctx->ops();

  for (size_t mod_idx = 0; mod_idx < ops.size(); ++mod_idx) {
    uint64_t *coeffs = poly.data(mod_idx);
    ops[mod_idx].BackwardInPlaceLazy(coeffs);
  }

  poly.override_representation(::bfv::math::Representation::PowerBasis);
}

void ExtendOneToNtt(const Poly &poly,
                    const std::shared_ptr<const Context> &base_ctx,
                    const std::shared_ptr<const Context> &mul_ctx,
                    const AuxiliaryLiftBackend &params, Poly &out, bool profile,
                    int64_t &t_copy_q_us, int64_t &t_scale_q_us,
                    int64_t &t_conv_aux_us, int64_t &t_conv_correction_us,
                    int64_t &t_aux_fix_us, int64_t &t_aux_ntt_us,
                    bool skip_base_q_ntt = false) {
  const auto &converters = params.converters;
  const auto &correction = params.correction;
  const size_t degree = base_ctx->degree();
  const size_t base_q_size = converters.base_q_size;
  const size_t aux_size = converters.aux_size;
  const uint64_t correction_mask = correction.correction_modulus - 1;
  const auto &base_ops = base_ctx->ops();
  const auto &mul_ops = mul_ctx->ops();
  const auto &base_moduli = base_ctx->rns()->moduli();
  const auto &aux_moduli = converters.aux_basis_ctx->moduli();
  const auto representation = poly.representation();

  if (!skip_base_q_ntt) {
    const auto copy_q_begin = profile ? Clock::now() : Clock::time_point{};
    for (size_t i = 0; i < base_q_size; ++i) {
      uint64_t *out_q = out.data(i);
      std::copy_n(poly.data(i), degree, out_q);
      if (representation == ::bfv::math::Representation::PowerBasis) {
        base_ops[i].ForwardInPlaceLazy(out_q);
      }
    }
    if (profile) {
      t_copy_q_us += micros_between(copy_q_begin, Clock::now());
    }
  }

  if (aux_size == 0) {
    return;
  }

  thread_local std::vector<uint64_t> tl_poly_scratch;
  const size_t q_scratch_offset = 0;
  const size_t augmented_aux_scratch_offset = base_q_size * degree;
  const size_t poly_alloc_size = augmented_aux_scratch_offset + degree;
  if (tl_poly_scratch.size() < poly_alloc_size) {
    tl_poly_scratch.resize(poly_alloc_size);
  }
  uint64_t *poly_scratch = tl_poly_scratch.data();

  constexpr size_t kMaxBaseConverterSize = 33;
  if (base_q_size > kMaxBaseConverterSize ||
      aux_size + 1 > kMaxBaseConverterSize) {
    throw std::runtime_error(
        "Aux-base extender base size exceeds pointer cache bound");
  }

  std::array<uint64_t *, kMaxBaseConverterSize> temp_q_mut_ptrs{};
  std::array<const uint64_t *, kMaxBaseConverterSize> temp_q_ptrs{};
  std::array<uint64_t *, kMaxBaseConverterSize> temp_aux_ptrs{};
  std::array<uint64_t *, 1> temp_correction_ptrs{};
  for (size_t i = 0; i < base_q_size; ++i) {
    temp_q_mut_ptrs[i] = poly_scratch + q_scratch_offset + i * degree;
    temp_q_ptrs[i] = temp_q_mut_ptrs[i];
  }
  for (size_t j = 0; j < aux_size; ++j) {
    temp_aux_ptrs[j] = out.data(base_q_size + j);
  }
  temp_correction_ptrs[0] = poly_scratch + augmented_aux_scratch_offset;

  const auto scale_q_begin = profile ? Clock::now() : Clock::time_point{};
  for (size_t i = 0; i < base_q_size; ++i) {
    uint64_t *scaled_q = poly_scratch + q_scratch_offset + i * degree;
    const uint64_t scale = correction.correction_modulus_mod_q[i];
    if (representation == ::bfv::math::Representation::PowerBasis) {
      base_moduli[i].ScalarMulTo(scaled_q, poly.data(i), degree, scale);
    } else {
      std::copy_n(poly.data(i), degree, scaled_q);
      base_ops[i].BackwardInPlaceLazyScaled(scaled_q, scale);
    }
  }
  if (profile) {
    t_scale_q_us += micros_between(scale_q_begin, Clock::now());
  }

  uint64_t *correction_words = temp_correction_ptrs[0];
  if (converters.main_to_augmented_aux_converter) {
    std::array<uint64_t *, kMaxBaseConverterSize> temp_augmented_aux_ptrs{};
    for (size_t j = 0; j < aux_size; ++j) {
      temp_augmented_aux_ptrs[j] = temp_aux_ptrs[j];
    }
    temp_augmented_aux_ptrs[aux_size] = correction_words;
    const auto conv_aux_begin = profile ? Clock::now() : Clock::time_point{};
    converters.main_to_augmented_aux_converter->fast_convert_array(
        temp_q_ptrs.data(), temp_augmented_aux_ptrs.data(), degree);
    if (profile) {
      t_conv_aux_us += micros_between(conv_aux_begin, Clock::now());
    }
  } else {
    const auto conv_aux_begin = profile ? Clock::now() : Clock::time_point{};
    converters.main_to_aux_converter->fast_convert_array(
        temp_q_ptrs.data(), temp_aux_ptrs.data(), degree);
    if (profile) {
      t_conv_aux_us += micros_between(conv_aux_begin, Clock::now());
    }

    const auto conv_correction_begin =
        profile ? Clock::now() : Clock::time_point{};
    converters.main_to_correction_converter->fast_convert_array(
        temp_q_ptrs.data(), temp_correction_ptrs.data(), degree);
    if (profile) {
      t_conv_correction_us +=
          micros_between(conv_correction_begin, Clock::now());
    }
  }

  const auto conv_correction_begin =
      profile ? Clock::now() : Clock::time_point{};
  for (size_t k = 0; k < degree; ++k) {
    correction_words[k] =
        mul_mod_2k(correction_words[k],
                   correction.neg_inv_prod_q_mod_correction, correction_mask);
  }
  if (profile) {
    t_conv_correction_us += micros_between(conv_correction_begin, Clock::now());
  }

  const auto aux_fix_begin = profile ? Clock::now() : Clock::time_point{};
  thread_local std::vector<uint64_t> tl_aux_fix_tmp;
  if (tl_aux_fix_tmp.size() < degree) {
    tl_aux_fix_tmp.resize(degree);
  }
  uint64_t *aux_fix_tmp = tl_aux_fix_tmp.data();
  for (size_t j = 0; j < aux_size; ++j) {
    const auto &bsk = aux_moduli[j];
    const uint64_t p_minus_correction = bsk.P() - correction.correction_modulus;
    const uint64_t prod_q = correction.prod_q_mod_aux_basis[j];
    const uint64_t inv_correction =
        correction.inv_correction_modulus_mod_aux[j];
    uint64_t *bsk_coeffs = temp_aux_ptrs[j];

    for (size_t k = 0; k < degree; ++k) {
      uint64_t centered_r = correction_words[k];
      if (centered_r >= correction.correction_modulus_div_2) {
        centered_r += p_minus_correction;
      }
      aux_fix_tmp[k] = centered_r;
    }
    bsk.ScalarMulVec(aux_fix_tmp, degree, prod_q);
    bsk.AddVec(aux_fix_tmp, bsk_coeffs, degree);
    bsk.ScalarMulVec(aux_fix_tmp, degree, inv_correction);
    std::copy_n(aux_fix_tmp, degree, bsk_coeffs);
  }
  if (profile) {
    t_aux_fix_us += micros_between(aux_fix_begin, Clock::now());
  }

  const auto aux_ntt_begin = profile ? Clock::now() : Clock::time_point{};
  for (size_t j = 0; j < aux_size; ++j) {
    mul_ops[base_q_size + j].ForwardInPlaceLazy(out.data(base_q_size + j));
  }
  if (profile) {
    t_aux_ntt_us += micros_between(aux_ntt_begin, Clock::now());
  }
}
}  // namespace

void AuxBaseExtender::ExtendToNtt(
    const std::vector<const Poly *> &polys,
    const std::shared_ptr<const Context> &base_ctx,
    const std::shared_ptr<const Context> &mul_ctx,
    const AuxiliaryLiftBackend &params, std::vector<Poly> &out,
    util::ArenaHandle pool) {
  const auto &converters = params.converters;
  const auto &correction = params.correction;
  const bool profile = heu_lift_profile_enabled();
  const auto total_begin = profile ? Clock::now() : Clock::time_point{};
  int64_t t_copy_q_us = 0;
  int64_t t_scale_q_us = 0;
  int64_t t_conv_aux_us = 0;
  int64_t t_conv_correction_us = 0;
  int64_t t_aux_fix_us = 0;
  int64_t t_aux_ntt_us = 0;

  if (polys.empty()) {
    out.clear();
    return;
  }

  if ((!converters.main_to_augmented_aux_converter &&
       (!converters.main_to_aux_converter ||
        !converters.main_to_correction_converter)) ||
      !converters.aux_basis_ctx) {
    throw std::runtime_error(
        "Auxiliary lifting precomputation is not initialized");
  }

  const size_t base_q_size = converters.base_q_size;
  const size_t aux_size = converters.aux_size;
  const size_t degree = base_ctx->degree();
  const size_t poly_count = polys.size();
  if (out.size() != poly_count) {
    out.clear();
    out.reserve(poly_count);
  }

  bool all_power_basis = true;
  for (size_t poly_idx = 0; poly_idx < poly_count; ++poly_idx) {
    const Poly *poly = polys[poly_idx];
    all_power_basis &=
        poly->representation() == ::bfv::math::Representation::PowerBasis;
    if (out.size() < poly_count || out[poly_idx].ctx() != mul_ctx) {
      Poly ext =
          Poly::uninitialized(mul_ctx, ::bfv::math::Representation::Ntt, pool);
      if (poly->allows_variable_time_computations()) {
        ext.allow_variable_time_computations();
      }
      if (out.size() < poly_count) {
        out.emplace_back(std::move(ext));
      } else {
        out[poly_idx] = std::move(ext);
      }
    } else {
      // This function overwrites every modulus slice, so scratch outputs only
      // need the representation flag reset instead of an actual conversion.
      if (out[poly_idx].representation() != ::bfv::math::Representation::Ntt) {
        out[poly_idx].override_representation(::bfv::math::Representation::Ntt);
      }
      if (poly->allows_variable_time_computations()) {
        out[poly_idx].allow_variable_time_computations();
      } else {
        out[poly_idx].disallow_variable_time_computations();
      }
    }
  }

  const bool use_batch_q_ntt4 =
      (poly_count == 4 && all_power_basis && !heu_batch_ntt_enabled() &&
       heu_batch_q_ntt4_enabled());
  if (use_batch_q_ntt4) {
    const auto copy_q_begin = profile ? Clock::now() : Clock::time_point{};
    for (size_t i = 0; i < base_q_size; ++i) {
      uint64_t *out0 = out[0].data(i);
      uint64_t *out1 = out[1].data(i);
      uint64_t *out2 = out[2].data(i);
      uint64_t *out3 = out[3].data(i);
      std::copy_n(polys[0]->data(i), degree, out0);
      std::copy_n(polys[1]->data(i), degree, out1);
      std::copy_n(polys[2]->data(i), degree, out2);
      std::copy_n(polys[3]->data(i), degree, out3);

      const auto *tables = base_ctx->ops()[i].GetNTTTables();
      if (tables) {
        ::bfv::math::ntt::HarveyNTT::HarveyNttLazy4(out0, out1, out2, out3,
                                                    *tables);
      } else {
        base_ctx->ops()[i].ForwardInPlaceLazy(out0);
        base_ctx->ops()[i].ForwardInPlaceLazy(out1);
        base_ctx->ops()[i].ForwardInPlaceLazy(out2);
        base_ctx->ops()[i].ForwardInPlaceLazy(out3);
      }
    }
    if (profile) {
      t_copy_q_us = micros_between(copy_q_begin, Clock::now());
    }
  }

  if (poly_count == 4 && all_power_basis && heu_batch_ntt_enabled()) {
    const auto copy_q_begin = profile ? Clock::now() : Clock::time_point{};
    for (size_t i = 0; i < base_q_size; ++i) {
      uint64_t *out0 = out[0].data(i);
      uint64_t *out1 = out[1].data(i);
      uint64_t *out2 = out[2].data(i);
      uint64_t *out3 = out[3].data(i);
      std::copy_n(polys[0]->data(i), degree, out0);
      std::copy_n(polys[1]->data(i), degree, out1);
      std::copy_n(polys[2]->data(i), degree, out2);
      std::copy_n(polys[3]->data(i), degree, out3);

      const auto *tables = base_ctx->ops()[i].GetNTTTables();
      if (tables) {
        ::bfv::math::ntt::HarveyNTT::HarveyNttLazy4(out0, out1, out2, out3,
                                                    *tables);
      } else {
        base_ctx->ops()[i].ForwardInPlaceLazy(out0);
        base_ctx->ops()[i].ForwardInPlaceLazy(out1);
        base_ctx->ops()[i].ForwardInPlaceLazy(out2);
        base_ctx->ops()[i].ForwardInPlaceLazy(out3);
      }
    }
    if (profile) {
      t_copy_q_us = micros_between(copy_q_begin, Clock::now());
    }
  }

  if (aux_size == 0 && poly_count == 4 && all_power_basis &&
      heu_batch_ntt_enabled()) {
    return;
  }

  const size_t total_count = degree * poly_count;

  if (poly_count == 4 && all_power_basis && heu_batch_ntt_enabled()) {
    const uint64_t correction_mask = correction.correction_modulus - 1;
    const auto &aux_moduli = converters.aux_basis_ctx->moduli();
    const auto &mul_ops = mul_ctx->ops();
    thread_local std::vector<uint64_t> tl_poly_scratch;
    const size_t q_scratch_offset = 0;
    const size_t augmented_aux_scratch_offset = base_q_size * degree;
    const size_t poly_alloc_size = augmented_aux_scratch_offset + degree;
    if (tl_poly_scratch.size() < poly_alloc_size) {
      tl_poly_scratch.resize(poly_alloc_size);
    }
    uint64_t *poly_scratch = tl_poly_scratch.data();

    constexpr size_t kMaxBaseConverterSize = 33;
    if (base_q_size > kMaxBaseConverterSize ||
        aux_size + 1 > kMaxBaseConverterSize) {
      throw std::runtime_error(
          "Aux-base extender base size exceeds pointer cache bound");
    }

    std::array<uint64_t *, kMaxBaseConverterSize> temp_q_scratch_ptrs{};
    std::array<const uint64_t *, kMaxBaseConverterSize> temp_q_ptrs{};
    std::array<uint64_t *, kMaxBaseConverterSize> temp_aux_ptrs{};
    std::array<uint64_t *, 1> temp_correction_ptrs{};
    for (size_t i = 0; i < base_q_size; ++i) {
      temp_q_scratch_ptrs[i] = poly_scratch + q_scratch_offset + i * degree;
      temp_q_ptrs[i] = temp_q_scratch_ptrs[i];
    }
    temp_correction_ptrs[0] = poly_scratch + augmented_aux_scratch_offset;
    thread_local std::vector<uint64_t> tl_aux_fix_tmp;
    if (tl_aux_fix_tmp.size() < degree) {
      tl_aux_fix_tmp.resize(degree);
    }
    uint64_t *aux_fix_tmp = tl_aux_fix_tmp.data();

    const auto *input_moduli = base_ctx->rns()->moduli().data();
    for (size_t poly_idx = 0; poly_idx < poly_count; ++poly_idx) {
      const Poly *poly = polys[poly_idx];
      for (size_t j = 0; j < aux_size; ++j) {
        temp_aux_ptrs[j] = out[poly_idx].data(base_q_size + j);
      }
      const auto scale_q_begin = profile ? Clock::now() : Clock::time_point{};
      for (size_t i = 0; i < base_q_size; ++i) {
        input_moduli[i].ScalarMulTo(temp_q_scratch_ptrs[i], poly->data(i),
                                    degree,
                                    correction.correction_modulus_mod_q[i]);
      }
      if (profile) {
        t_scale_q_us += micros_between(scale_q_begin, Clock::now());
      }

      uint64_t *correction_words = temp_correction_ptrs[0];
      if (converters.main_to_augmented_aux_converter) {
        std::array<uint64_t *, kMaxBaseConverterSize> temp_augmented_aux_ptrs{};
        for (size_t j = 0; j < aux_size; ++j) {
          temp_augmented_aux_ptrs[j] = temp_aux_ptrs[j];
        }
        temp_augmented_aux_ptrs[aux_size] = correction_words;
        const auto conv_aux_begin =
            profile ? Clock::now() : Clock::time_point{};
        converters.main_to_augmented_aux_converter->fast_convert_array(
            temp_q_ptrs.data(), temp_augmented_aux_ptrs.data(), degree);
        if (profile) {
          t_conv_aux_us += micros_between(conv_aux_begin, Clock::now());
        }
      } else {
        const auto conv_aux_begin =
            profile ? Clock::now() : Clock::time_point{};
        converters.main_to_aux_converter->fast_convert_array(
            temp_q_ptrs.data(), temp_aux_ptrs.data(), degree);
        if (profile) {
          t_conv_aux_us += micros_between(conv_aux_begin, Clock::now());
        }

        const auto conv_correction_begin =
            profile ? Clock::now() : Clock::time_point{};
        converters.main_to_correction_converter->fast_convert_array(
            temp_q_ptrs.data(), temp_correction_ptrs.data(), degree);
        if (profile) {
          t_conv_correction_us +=
              micros_between(conv_correction_begin, Clock::now());
        }
      }
      const auto conv_correction_begin =
          profile ? Clock::now() : Clock::time_point{};
      for (size_t k = 0; k < degree; ++k) {
        correction_words[k] = mul_mod_2k(
            correction_words[k], correction.neg_inv_prod_q_mod_correction,
            correction_mask);
      }
      if (profile) {
        t_conv_correction_us +=
            micros_between(conv_correction_begin, Clock::now());
      }

      const auto aux_fix_begin = profile ? Clock::now() : Clock::time_point{};
      for (size_t j = 0; j < aux_size; ++j) {
        const auto &bsk = aux_moduli[j];
        const uint64_t p_minus_correction =
            bsk.P() - correction.correction_modulus;
        const uint64_t prod_q = correction.prod_q_mod_aux_basis[j];
        const uint64_t inv_correction =
            correction.inv_correction_modulus_mod_aux[j];
        uint64_t *bsk_coeffs = temp_aux_ptrs[j];

        for (size_t k = 0; k < degree; ++k) {
          uint64_t centered_r = correction_words[k];
          if (centered_r >= correction.correction_modulus_div_2) {
            centered_r += p_minus_correction;
          }
          aux_fix_tmp[k] = centered_r;
        }
        bsk.ScalarMulVec(aux_fix_tmp, degree, prod_q);
        bsk.AddVec(aux_fix_tmp, bsk_coeffs, degree);
        bsk.ScalarMulVec(aux_fix_tmp, degree, inv_correction);
        std::copy_n(aux_fix_tmp, degree, bsk_coeffs);
      }
      if (profile) {
        t_aux_fix_us += micros_between(aux_fix_begin, Clock::now());
      }
    }
    const auto aux_ntt_begin = profile ? Clock::now() : Clock::time_point{};
    for (size_t j = 0; j < aux_size; ++j) {
      uint64_t *s0 = out[0].data(base_q_size + j);
      uint64_t *s1 = out[1].data(base_q_size + j);
      uint64_t *s2 = out[2].data(base_q_size + j);
      uint64_t *s3 = out[3].data(base_q_size + j);
      const auto *tables = mul_ops[base_q_size + j].GetNTTTables();
      if (tables) {
        ::bfv::math::ntt::HarveyNTT::HarveyNttLazy4(s0, s1, s2, s3, *tables);
      } else {
        mul_ops[base_q_size + j].ForwardInPlaceLazy(s0);
        mul_ops[base_q_size + j].ForwardInPlaceLazy(s1);
        mul_ops[base_q_size + j].ForwardInPlaceLazy(s2);
        mul_ops[base_q_size + j].ForwardInPlaceLazy(s3);
      }
    }
    if (profile) {
      t_aux_ntt_us = micros_between(aux_ntt_begin, Clock::now());
      const auto total_us = micros_between(total_begin, Clock::now());
      std::cerr << "[HEU_LIFT_PROFILE] poly_count=" << poly_count
                << " count=" << total_count << " copy_q_us=" << t_copy_q_us
                << " scale_q_us=" << t_scale_q_us
                << " conv_aux_us=" << t_conv_aux_us
                << " conv_correction_us=" << t_conv_correction_us
                << " baseconv_us=" << (t_conv_aux_us + t_conv_correction_us)
                << " aux_fix_us=" << t_aux_fix_us
                << " aux_ntt_us=" << t_aux_ntt_us << " total_us=" << total_us
                << '\n';
    }
    return;
  }

  for (size_t poly_idx = 0; poly_idx < poly_count; ++poly_idx) {
    ExtendOneToNtt(*polys[poly_idx], base_ctx, mul_ctx, params, out[poly_idx],
                   profile, t_copy_q_us, t_scale_q_us, t_conv_aux_us,
                   t_conv_correction_us, t_aux_fix_us, t_aux_ntt_us,
                   use_batch_q_ntt4);
  }
  if (profile) {
    const auto total_us = micros_between(total_begin, Clock::now());
    std::cerr << "[HEU_LIFT_PROFILE] poly_count=" << poly_count
              << " count=" << total_count << " copy_q_us=" << t_copy_q_us
              << " scale_q_us=" << t_scale_q_us
              << " conv_aux_us=" << t_conv_aux_us
              << " conv_correction_us=" << t_conv_correction_us
              << " baseconv_us=" << (t_conv_aux_us + t_conv_correction_us)
              << " aux_fix_us=" << t_aux_fix_us
              << " aux_ntt_us=" << t_aux_ntt_us << " total_us=" << total_us
              << '\n';
  }
}

}  // namespace math
}  // namespace bfv
