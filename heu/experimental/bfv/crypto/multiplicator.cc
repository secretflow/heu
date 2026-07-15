#include "crypto/multiplicator.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <future>
#include <iostream>
#include <optional>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/exceptions.h"
#include "crypto/relinearization_key.h"
#include "math/aux_base_extender.h"
#include "math/aux_base_plan.h"
#include "math/base_converter.h"
#include "math/biguint.h"
#include "math/modulus.h"
#include "math/ntt_harvey.h"
#include "math/poly.h"
#include "math/primes.h"
#include "math/rns_context.h"
#include "math/scaling_factor.h"
#include "util/arena_allocator.h"
#include "util/profiler.h"

namespace {
using ::bfv::math::rns::BaseConverter;
using ::bfv::math::rns::RnsContext;
using ::bfv::math::rq::Context;
using ::bfv::math::rq::Poly;
using ::bfv::util::ArenaHandle;

using Clock = std::chrono::steady_clock;

inline bool heu_mul_profile_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_MUL_PROFILE");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline bool heu_mul_lift_parallel_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_ENABLE_MUL_LIFT_PARALLEL");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline bool heu_force_separate_lift_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_FORCE_SEPARATE_LIFT");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline bool heu_batch_lift_enabled() {
  static const bool enabled = [] {
    const char *disable_env = std::getenv("HEU_BFV_DISABLE_BATCH_LIFT");
    if (disable_env && disable_env[0] != '\0' && disable_env[0] != '0') {
      return false;
    }
    const char *env = std::getenv("HEU_BFV_ENABLE_BATCH_LIFT");
    if (env && env[0] != '\0' && env[0] != '0') {
      return true;
    }
    return true;
  }();
  return enabled;
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

inline int64_t micros_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
      .count();
}

void FusedInverseLazyAddPair(::bfv::math::rq::Poly &delta0_ntt,
                             ::bfv::math::rq::Poly &delta1_ntt,
                             ::bfv::math::rq::Poly &target0_power,
                             ::bfv::math::rq::Poly &target1_power) {
  auto ctx = delta0_ntt.ctx();
  const size_t degree = ctx->degree();
  const auto &ops = ctx->ops();
  const auto &q_ops = ctx->q();

  for (size_t mod_idx = 0; mod_idx < q_ops.size(); ++mod_idx) {
    uint64_t *d0 = delta0_ntt.data(mod_idx);
    uint64_t *d1 = delta1_ntt.data(mod_idx);
    uint64_t *t0 = target0_power.data(mod_idx);
    uint64_t *t1 = target1_power.data(mod_idx);
    const auto *tables = ops[mod_idx].GetNTTTables();

    if (tables) {
      ::bfv::math::ntt::HarveyNTT::InverseHarveyNttLazy2(d0, d1, *tables);
      for (size_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        t0[coeff_idx] = q_ops[mod_idx].Add(
            t0[coeff_idx], q_ops[mod_idx].Reduce(d0[coeff_idx]));
        t1[coeff_idx] = q_ops[mod_idx].Add(
            t1[coeff_idx], q_ops[mod_idx].Reduce(d1[coeff_idx]));
      }
    } else {
      ops[mod_idx].BackwardInPlace(d0);
      ops[mod_idx].BackwardInPlace(d1);
      q_ops[mod_idx].AddVec(t0, d0, degree);
      q_ops[mod_idx].AddVec(t1, d1, degree);
    }
  }
}

inline void ChangeToPowerBasisLazy(::bfv::math::rq::Poly &poly) {
  using ::bfv::math::rq::Representation;
  if (poly.representation() == Representation::PowerBasis) {
    return;
  }
  if (poly.representation() == Representation::NttShoup) {
    poly.change_representation(Representation::Ntt);
  }
  if (poly.representation() != Representation::Ntt) {
    throw std::runtime_error(
        "Expected Ntt/NttShoup representation before lazy inverse NTT");
  }

  auto ctx = poly.ctx();
  const auto &ops = ctx->ops();
  for (size_t i = 0; i < ops.size(); ++i) {
    ops[i].BackwardInPlaceLazy(poly.data(i));
  }
  poly.override_representation(Representation::PowerBasis);
}

inline void ChangeThreeToPowerBasisLazy(::bfv::math::rq::Poly &a,
                                        ::bfv::math::rq::Poly &b,
                                        ::bfv::math::rq::Poly &c) {
  using ::bfv::math::rq::Representation;
  auto normalize = [](Poly &p) {
    if (p.representation() == Representation::NttShoup) {
      p.change_representation(Representation::Ntt);
    }
  };
  normalize(a);
  normalize(b);
  normalize(c);

  if (a.representation() == Representation::PowerBasis &&
      b.representation() == Representation::PowerBasis &&
      c.representation() == Representation::PowerBasis) {
    return;
  }

  if (a.representation() != Representation::Ntt ||
      b.representation() != Representation::Ntt ||
      c.representation() != Representation::Ntt || a.ctx() != b.ctx() ||
      a.ctx() != c.ctx()) {
    // Conservative fallback keeps behavior for mixed contexts/representations.
    ChangeToPowerBasisLazy(a);
    ChangeToPowerBasisLazy(b);
    ChangeToPowerBasisLazy(c);
    return;
  }

  const auto &ops = a.ctx()->ops();
  for (size_t i = 0; i < ops.size(); ++i) {
    const auto *tables = ops[i].GetNTTTables();
    if (!tables) {
      ChangeToPowerBasisLazy(a);
      ChangeToPowerBasisLazy(b);
      ChangeToPowerBasisLazy(c);
      return;
    }
    ::bfv::math::ntt::HarveyNTT::InverseHarveyNttLazy3(a.data(i), b.data(i),
                                                       c.data(i), *tables);
  }
  a.override_representation(Representation::PowerBasis);
  b.override_representation(Representation::PowerBasis);
  c.override_representation(Representation::PowerBasis);
}

#if defined(HEU_BFV_MUL_USE_AUX_BASE) && HEU_BFV_MUL_USE_AUX_BASE
// This #if block was incorrectly placed and contained a closing brace for the
// anonymous namespace. It is being closed here to resolve the unterminated #if
// issue.
#endif

}  // anonymous namespace

namespace crypto {
namespace bfv {

struct MultiplyProfile {
  bool enabled = false;
  Clock::time_point total_begin{};
  int64_t t_lift_lhs_us = 0;
  int64_t t_lift_rhs_us = 0;
  int64_t t_lift_total_us = 0;
  int64_t t_tensor_us = 0;
  int64_t t_to_power_us = 0;
  int64_t t_downscale_us = 0;
  int64_t t_relin_us = 0;
  int64_t t_relin_key_switch_us = 0;
  int64_t t_relin_modswitch_us = 0;
  int64_t t_relin_repr_us = 0;
  int64_t t_relin_add_us = 0;
  int64_t t_to_ntt_out_us = 0;
  int64_t t_modswitch_us = 0;
  int64_t t_result_build_us = 0;
  const char *lift_mode = "none";

  explicit MultiplyProfile(bool profile_enabled)
      : enabled(profile_enabled),
        total_begin(profile_enabled ? Clock::now() : Clock::time_point{}) {}

  void emit(bool with_relinearization) const {
    if (!enabled) {
      return;
    }
    const auto total_us = micros_between(total_begin, Clock::now());
    std::cerr << "[HEU_MUL_PROFILE] mode="
              << (with_relinearization ? "mul_relin" : "mul")
              << " lift_mode=" << lift_mode << " lift_lhs_us=" << t_lift_lhs_us
              << " lift_rhs_us=" << t_lift_rhs_us
              << " lift_total_us=" << t_lift_total_us
              << " tensor_us=" << t_tensor_us
              << " to_power_us=" << t_to_power_us
              << " downscale_us=" << t_downscale_us
              << " relin_us=" << t_relin_us
              << " relin_key_switch_us=" << t_relin_key_switch_us
              << " relin_modswitch_us=" << t_relin_modswitch_us
              << " relin_repr_us=" << t_relin_repr_us
              << " relin_add_us=" << t_relin_add_us
              << " result_build_us=" << t_result_build_us
              << " to_ntt_out_us=" << t_to_ntt_out_us
              << " modswitch_us=" << t_modswitch_us << " total_us=" << total_us
              << '\n';
  }
};

struct LiftedOperands {
  ::bfv::math::rq::Poly *lhs0 = nullptr;
  ::bfv::math::rq::Poly *lhs1 = nullptr;
  const ::bfv::math::rq::Poly *rhs0 = nullptr;
  const ::bfv::math::rq::Poly *rhs1 = nullptr;
  ::bfv::math::rq::Poly c2_storage;
  const char *lift_mode = "none";
};

/**
 * @brief Implementation class for Multiplicator using PIMPL pattern.
 */
class Multiplicator::Impl {
 public:
  std::shared_ptr<BfvParameters> parameters;
  std::unique_ptr<::bfv::math::rq::BasisMapper> lhs_lift_mapper;
  std::unique_ptr<::bfv::math::rq::BasisMapper> rhs_lift_mapper;
  std::unique_ptr<::bfv::math::rq::BasisMapper> post_mul_mapper;
#if defined(HEU_BFV_MUL_USE_AUX_BASE) && HEU_BFV_MUL_USE_AUX_BASE
  ::bfv::math::AuxiliaryLiftBackend aux_base_plan;
#endif
  size_t base_q_size;
  size_t aux_size;
  std::shared_ptr<const ::bfv::math::rq::Context> base_ctx;
  std::shared_ptr<const ::bfv::math::rq::Context> mul_ctx;
  std::unique_ptr<RelinearizationKey> relinearization_key;
  bool mod_switch;
  size_t level;

  Impl(std::shared_ptr<BfvParameters> params,
       std::unique_ptr<::bfv::math::rq::BasisMapper> lhs_lift,
       std::unique_ptr<::bfv::math::rq::BasisMapper> rhs_lift,
       std::unique_ptr<::bfv::math::rq::BasisMapper> post_mul,
       std::unique_ptr<::bfv::math::rns::BaseConverter> main_to_aux_converter,
       size_t q_size, size_t bsk_size,
       std::shared_ptr<const ::bfv::math::rq::Context> base_context,
       std::shared_ptr<const ::bfv::math::rq::Context> mul_context,
       size_t multiplication_level)
      : parameters(std::move(params)),
        lhs_lift_mapper(std::move(lhs_lift)),
        rhs_lift_mapper(std::move(rhs_lift)),
        post_mul_mapper(std::move(post_mul)),
        base_q_size(q_size),
        aux_size(bsk_size),
        base_ctx(std::move(base_context)),
        mul_ctx(std::move(mul_context)),
        relinearization_key(nullptr),
        mod_switch(false),
        level(multiplication_level) {
#if defined(HEU_BFV_MUL_USE_AUX_BASE) && HEU_BFV_MUL_USE_AUX_BASE
    aux_base_plan.converters.main_to_aux_converter =
        std::move(main_to_aux_converter);
#else
    (void)main_to_aux_converter;
#endif
  }

  void validate_inputs(const Ciphertext &lhs, const Ciphertext &rhs) const;
  LiftedOperands lift_operands(const Ciphertext &lhs, const Ciphertext &rhs,
                               MultiplyProfile &profile) const;
  std::vector<::bfv::math::rq::Poly> compute_downscaled_product(
      LiftedOperands &lifted, MultiplyProfile &profile) const;
  void apply_relinearization(std::vector<::bfv::math::rq::Poly> &result_polys,
                             MultiplyProfile &profile) const;
  Ciphertext finalize_result(std::vector<::bfv::math::rq::Poly> result_polys,
                             MultiplyProfile &profile) const;

 private:
  static void ensure_ntt_representation(
      std::vector<::bfv::math::rq::Poly> &polys);
};

void Multiplicator::Impl::validate_inputs(const Ciphertext &lhs,
                                          const Ciphertext &rhs) const {
  if (*lhs.parameters() != *parameters || *rhs.parameters() != *parameters) {
    throw ParameterException("Input ciphertexts use different parameter sets");
  }
  if (lhs.level() != level || rhs.level() != level) {
    throw ParameterException(
        "Input ciphertext levels do not match the multiplicator level");
  }
  if (lhs.size() != 2 || rhs.size() != 2) {
    throw ParameterException(
        "Ciphertext multiplication requires two-component inputs");
  }
}

void Multiplicator::Impl::ensure_ntt_representation(
    std::vector<::bfv::math::rq::Poly> &polys) {
  for (auto &poly : polys) {
    if (poly.representation() != ::bfv::math::rq::Representation::Ntt) {
      poly.change_representation(::bfv::math::rq::Representation::Ntt);
    }
  }
}

LiftedOperands Multiplicator::Impl::lift_operands(
    const Ciphertext &lhs, const Ciphertext &rhs,
    MultiplyProfile &profile) const {
  LiftedOperands lifted;
  std::vector<const ::bfv::math::rq::Poly *> lhs_polys = {
      &lhs.polynomial(0),
      &lhs.polynomial(1),
  };
  std::vector<const ::bfv::math::rq::Poly *> rhs_polys = {
      &rhs.polynomial(0),
      &rhs.polynomial(1),
  };

#if defined(HEU_BFV_MUL_USE_AUX_BASE) && HEU_BFV_MUL_USE_AUX_BASE
  if ((!aux_base_plan.converters.main_to_aux_converter &&
       !aux_base_plan.converters.main_to_augmented_aux_converter) ||
      !aux_base_plan.converters.aux_basis_ctx) {
    throw ParameterException("Aux-base lifting parameters are not initialized");
  }

  thread_local std::vector<::bfv::math::rq::Poly> tl_lhs_scaled;
  thread_local std::vector<::bfv::math::rq::Poly> tl_rhs_scaled;
  thread_local std::vector<::bfv::math::rq::Poly> tl_all_scaled;

  if (heu_mul_lift_parallel_enabled()) {
    PROFILE_BLOCK("Mul: Lift Parallel");
    lifted.lift_mode = "parallel2";
    const auto lift_begin =
        profile.enabled ? Clock::now() : Clock::time_point{};
    auto lhs_future = std::async(
        std::launch::async, [&]() -> std::vector<::bfv::math::rq::Poly> {
          std::vector<::bfv::math::rq::Poly> tmp;
          ::bfv::math::AuxBaseExtender::ExtendToNtt(
              lhs_polys, base_ctx, mul_ctx, aux_base_plan, tmp);
          return tmp;
        });
    ::bfv::math::AuxBaseExtender::ExtendToNtt(rhs_polys, base_ctx, mul_ctx,
                                              aux_base_plan, tl_rhs_scaled);
    tl_lhs_scaled = lhs_future.get();
    if (profile.enabled) {
      profile.t_lift_total_us = micros_between(lift_begin, Clock::now());
    }
    lifted.lhs0 = &tl_lhs_scaled[0];
    lifted.lhs1 = &tl_lhs_scaled[1];
    lifted.rhs0 = &tl_rhs_scaled[0];
    lifted.rhs1 = &tl_rhs_scaled[1];
  } else if (heu_force_separate_lift_enabled() || !heu_batch_lift_enabled()) {
    PROFILE_BLOCK("Mul: Lift Separate");
    lifted.lift_mode = "separate2";
    const auto lift_begin =
        profile.enabled ? Clock::now() : Clock::time_point{};
    ::bfv::math::AuxBaseExtender::ExtendToNtt(lhs_polys, base_ctx, mul_ctx,
                                              aux_base_plan, tl_lhs_scaled);
    ::bfv::math::AuxBaseExtender::ExtendToNtt(rhs_polys, base_ctx, mul_ctx,
                                              aux_base_plan, tl_rhs_scaled);
    if (profile.enabled) {
      profile.t_lift_total_us = micros_between(lift_begin, Clock::now());
    }
    lifted.lhs0 = &tl_lhs_scaled[0];
    lifted.lhs1 = &tl_lhs_scaled[1];
    lifted.rhs0 = &tl_rhs_scaled[0];
    lifted.rhs1 = &tl_rhs_scaled[1];
  } else {
    PROFILE_BLOCK("Mul: Lift Batch4");
    lifted.lift_mode = "batch4";
    const auto lift_begin =
        profile.enabled ? Clock::now() : Clock::time_point{};
    std::vector<const ::bfv::math::rq::Poly *> all_polys;
    all_polys.reserve(4);
    all_polys.push_back(lhs_polys[0]);
    all_polys.push_back(lhs_polys[1]);
    all_polys.push_back(rhs_polys[0]);
    all_polys.push_back(rhs_polys[1]);
    ::bfv::math::AuxBaseExtender::ExtendToNtt(all_polys, base_ctx, mul_ctx,
                                              aux_base_plan, tl_all_scaled);
    if (tl_all_scaled.size() != 4) {
      throw std::runtime_error("Unexpected aux-base lift output size");
    }
    if (profile.enabled) {
      profile.t_lift_total_us = micros_between(lift_begin, Clock::now());
    }
    lifted.lhs0 = &tl_all_scaled[0];
    lifted.lhs1 = &tl_all_scaled[1];
    lifted.rhs0 = &tl_all_scaled[2];
    lifted.rhs1 = &tl_all_scaled[3];
  }
  lifted.c2_storage = ::bfv::math::rq::Poly::uninitialized(
      lifted.lhs0->ctx(), ::bfv::math::rq::Representation::Ntt);
#else
  thread_local std::vector<::bfv::math::rq::Poly> tl_lhs_scaled;
  thread_local std::vector<::bfv::math::rq::Poly> tl_rhs_scaled;
  const auto lift_lhs_begin =
      profile.enabled ? Clock::now() : Clock::time_point{};
  lhs_lift_mapper->map_many_into(lhs_polys, tl_lhs_scaled);
  if (profile.enabled) {
    profile.t_lift_lhs_us = micros_between(lift_lhs_begin, Clock::now());
  }

  const auto lift_rhs_begin =
      profile.enabled ? Clock::now() : Clock::time_point{};
  rhs_lift_mapper->map_many_into(rhs_polys, tl_rhs_scaled);
  if (profile.enabled) {
    profile.t_lift_rhs_us = micros_between(lift_rhs_begin, Clock::now());
    profile.t_lift_total_us = profile.t_lift_lhs_us + profile.t_lift_rhs_us;
  }

  ensure_ntt_representation(tl_lhs_scaled);
  ensure_ntt_representation(tl_rhs_scaled);
  lifted.lift_mode = "separate2";
  lifted.lhs0 = &tl_lhs_scaled[0];
  lifted.lhs1 = &tl_lhs_scaled[1];
  lifted.rhs0 = &tl_rhs_scaled[0];
  lifted.rhs1 = &tl_rhs_scaled[1];
  lifted.c2_storage = ::bfv::math::rq::Poly::uninitialized(
      lifted.lhs0->ctx(), lifted.lhs0->representation());
#endif

  profile.lift_mode = lifted.lift_mode;
  return lifted;
}

std::vector<::bfv::math::rq::Poly>
Multiplicator::Impl::compute_downscaled_product(
    LiftedOperands &lifted, MultiplyProfile &profile) const {
  {
    PROFILE_BLOCK("Mul: Tensor");
    const auto tensor_begin =
        profile.enabled ? Clock::now() : Clock::time_point{};
    ::bfv::math::rq::Poly::tensor_product_inplace(*lifted.lhs0, *lifted.lhs1,
                                                  lifted.c2_storage,
                                                  *lifted.rhs0, *lifted.rhs1);
    if (profile.enabled) {
      profile.t_tensor_us = micros_between(tensor_begin, Clock::now());
    }
  }

  {
    PROFILE_BLOCK("Mul: To PowerBasis");
    const auto to_power_begin =
        profile.enabled ? Clock::now() : Clock::time_point{};
    ChangeThreeToPowerBasisLazy(*lifted.lhs0, *lifted.lhs1, lifted.c2_storage);
    if (profile.enabled) {
      profile.t_to_power_us = micros_between(to_power_begin, Clock::now());
    }
  }

  std::vector<const ::bfv::math::rq::Poly *> down_polys = {
      lifted.lhs0,
      lifted.lhs1,
      &lifted.c2_storage,
  };

  PROFILE_BLOCK("Mul: Downscale");
  const auto downscale_begin =
      profile.enabled ? Clock::now() : Clock::time_point{};
  auto result_polys = post_mul_mapper->map_many(down_polys);
  if (profile.enabled) {
    profile.t_downscale_us = micros_between(downscale_begin, Clock::now());
  }
  return result_polys;
}

void Multiplicator::Impl::apply_relinearization(
    std::vector<::bfv::math::rq::Poly> &result_polys,
    MultiplyProfile &profile) const {
  if (!relinearization_key) {
    return;
  }

  const auto relin_begin = profile.enabled ? Clock::now() : Clock::time_point{};
  const auto relin_ks_begin =
      profile.enabled ? Clock::now() : Clock::time_point{};
  thread_local ::bfv::math::rq::Poly tl_c0_delta;
  thread_local ::bfv::math::rq::Poly tl_c1_delta;
  const auto target_repr = result_polys[0].representation();
  const bool can_fuse_power_output =
      target_repr == ::bfv::math::rq::Representation::PowerBasis &&
      relinearization_key->ciphertext_level() ==
          relinearization_key->key_level();

  relinearization_key->relinearize_poly(
      result_polys[2], tl_c0_delta, tl_c1_delta,
      can_fuse_power_output ? ::bfv::math::rq::Representation::Ntt
                            : ::bfv::math::rq::Representation::PowerBasis);
  auto &c0_delta = tl_c0_delta;
  auto &c1_delta = tl_c1_delta;
  if (profile.enabled) {
    profile.t_relin_key_switch_us =
        micros_between(relin_ks_begin, Clock::now());
  }

  if (!can_fuse_power_output && c0_delta.ctx() != result_polys[0].ctx()) {
    const auto relin_modswitch_begin =
        profile.enabled ? Clock::now() : Clock::time_point{};
    c0_delta.drop_to_context(result_polys[0].ctx());
    c1_delta.drop_to_context(result_polys[1].ctx());
    if (profile.enabled) {
      profile.t_relin_modswitch_us =
          micros_between(relin_modswitch_begin, Clock::now());
    }
  }

  if (!can_fuse_power_output &&
      target_repr != ::bfv::math::rq::Representation::PowerBasis) {
    const auto relin_repr_begin =
        profile.enabled ? Clock::now() : Clock::time_point{};
    c0_delta.change_representation(target_repr);
    c1_delta.change_representation(target_repr);
    if (profile.enabled) {
      profile.t_relin_repr_us = micros_between(relin_repr_begin, Clock::now());
    }
  }

  const auto relin_add_begin =
      profile.enabled ? Clock::now() : Clock::time_point{};
  if (can_fuse_power_output) {
    FusedInverseLazyAddPair(c0_delta, c1_delta, result_polys[0],
                            result_polys[1]);
  } else {
    result_polys[0] += c0_delta;
    result_polys[1] += c1_delta;
  }
  result_polys.resize(2);
  if (profile.enabled) {
    profile.t_relin_add_us = micros_between(relin_add_begin, Clock::now());
    profile.t_relin_us = micros_between(relin_begin, Clock::now());
  }
}

Ciphertext Multiplicator::Impl::finalize_result(
    std::vector<::bfv::math::rq::Poly> result_polys,
    MultiplyProfile &profile) const {
  profile.t_to_ntt_out_us = 0;

  if (mod_switch) {
    const auto modswitch_begin =
        profile.enabled ? Clock::now() : Clock::time_point{};
    const auto result_build_begin =
        profile.enabled ? Clock::now() : Clock::time_point{};
    auto result = Ciphertext::from_polynomials_with_level(
        std::move(result_polys), parameters, level);
    if (profile.enabled) {
      profile.t_result_build_us =
          micros_between(result_build_begin, Clock::now());
    }

    result.mod_switch_to_next_level();
    if (profile.enabled) {
      profile.t_modswitch_us = micros_between(modswitch_begin, Clock::now());
    }
    profile.emit(relinearization_key != nullptr);
    return result;
  }

  const auto result_build_begin =
      profile.enabled ? Clock::now() : Clock::time_point{};
  auto result = Ciphertext::from_polynomials_with_level(std::move(result_polys),
                                                        parameters, level);
  if (profile.enabled) {
    profile.t_result_build_us =
        micros_between(result_build_begin, Clock::now());
  }
  profile.emit(relinearization_key != nullptr);
  return result;
}

Multiplicator::Multiplicator(std::unique_ptr<Impl> impl)
    : pImpl(std::move(impl)) {}

Multiplicator::~Multiplicator() = default;

Multiplicator::Multiplicator(Multiplicator &&) noexcept = default;
Multiplicator &Multiplicator::operator=(Multiplicator &&) noexcept = default;

std::unique_ptr<Multiplicator> Multiplicator::create(
    const ::bfv::math::rns::ScalingFactor &lhs_scaling_factor,
    const ::bfv::math::rns::ScalingFactor &rhs_scaling_factor,
    const std::vector<uint64_t> &extended_basis,
    const ::bfv::math::rns::ScalingFactor &post_mul_scaling_factor,
    std::shared_ptr<BfvParameters> parameters) {
  return create_leveled_internal(lhs_scaling_factor, rhs_scaling_factor,
                                 extended_basis, post_mul_scaling_factor, 0,
                                 std::move(parameters));
}

std::unique_ptr<Multiplicator> Multiplicator::create_leveled(
    const ::bfv::math::rns::ScalingFactor &lhs_scaling_factor,
    const ::bfv::math::rns::ScalingFactor &rhs_scaling_factor,
    const std::vector<uint64_t> &extended_basis,
    const ::bfv::math::rns::ScalingFactor &post_mul_scaling_factor,
    size_t level, std::shared_ptr<BfvParameters> parameters) {
  return create_leveled_internal(lhs_scaling_factor, rhs_scaling_factor,
                                 extended_basis, post_mul_scaling_factor, level,
                                 std::move(parameters));
}

std::unique_ptr<Multiplicator> Multiplicator::create_default(
    const RelinearizationKey &relinearization_key) {
  auto params = relinearization_key.parameters();
  auto ctx = params->ctx_at_level(relinearization_key.ciphertext_level());

  size_t total_coeff_bit_count = 0;
  auto moduli_sizes = params->moduli_sizes();
  for (size_t i = 0; i < ctx->moduli().size(); ++i) {
    total_coeff_bit_count += moduli_sizes[i];
  }

  size_t plain_modulus_bit_count = 0;
  uint64_t plain_modulus = params->plaintext_modulus();
  while (plain_modulus > 0) {
    ++plain_modulus_bit_count;
    plain_modulus >>= 1;
  }
  if (plain_modulus_bit_count == 0) {
    plain_modulus_bit_count = 1;
  }

  constexpr size_t kInternalAuxModBitCount = 61;
  size_t base_B_size = ctx->moduli().size();
  if (32 + plain_modulus_bit_count + total_coeff_bit_count >=
      kInternalAuxModBitCount * ctx->moduli().size() +
          kInternalAuxModBitCount) {
    ++base_B_size;
  }
  const size_t base_Bsk_size = base_B_size + 1;
  const size_t base_Bsk_m_tilde_size = base_Bsk_size + 1;

  std::vector<uint64_t> sampled_primes;
  sampled_primes.reserve(base_Bsk_m_tilde_size);
  uint64_t upper_bound = 1ULL << kInternalAuxModBitCount;
  while (sampled_primes.size() < base_Bsk_m_tilde_size) {
    auto prime_opt = ::bfv::math::zq::generate_prime(
        kInternalAuxModBitCount, 2 * params->degree(), upper_bound);
    if (!prime_opt) {
      throw MathException("Failed to generate prime for extended basis");
    }
    upper_bound = *prime_opt;

    // Check if prime is already in the basis
    bool found = false;
    for (uint64_t existing : sampled_primes) {
      if (existing == upper_bound) {
        found = true;
        break;
      }
    }
    for (uint64_t existing : ctx->moduli()) {
      if (existing == upper_bound) {
        found = true;
        break;
      }
    }

    if (!found) {
      sampled_primes.push_back(upper_bound);
    }
  }

  std::vector<uint64_t> extended_basis;
  extended_basis.reserve(ctx->moduli().size() + base_Bsk_size);
  for (uint64_t modulus : ctx->moduli()) {
    extended_basis.push_back(modulus);
  }

  const uint64_t m_sk = sampled_primes[0];
  for (size_t i = 2; i < sampled_primes.size(); ++i) {
    extended_basis.push_back(sampled_primes[i]);
  }
  extended_basis.push_back(m_sk);

  // Create scaling factors
  auto one_factor = ::bfv::math::rns::ScalingFactor::one();
  // BFV multiplication requires scaling by t/q
  auto post_mul_factor = ::bfv::math::rns::ScalingFactor(
      ::bfv::math::rns::BigUint(params->plaintext_modulus()),
      ::bfv::math::rns::BigUint(ctx->modulus()));

  auto multiplicator = create_leveled_internal(
      one_factor, one_factor, extended_basis, post_mul_factor,
      relinearization_key.ciphertext_level(), params);

  multiplicator->enable_relinearization(relinearization_key);
  return multiplicator;
}

std::unique_ptr<Multiplicator> Multiplicator::create_leveled_internal(
    const ::bfv::math::rns::ScalingFactor &lhs_scaling_factor,
    const ::bfv::math::rns::ScalingFactor &rhs_scaling_factor,
    const std::vector<uint64_t> &extended_basis,
    const ::bfv::math::rns::ScalingFactor &post_mul_scaling_factor,
    size_t level, std::shared_ptr<BfvParameters> parameters) {
  if (!parameters) {
    throw ParameterException("Parameters cannot be null");
  }

  auto base_ctx = parameters->ctx_at_level(level);

  // Create multiplication context without timing overhead
  auto mul_ctx =
      ::bfv::math::rq::Context::create(extended_basis, parameters->degree());

  auto post_mul_mapper = ::bfv::math::rq::BasisMapper::create(
      mul_ctx, base_ctx, post_mul_scaling_factor);

  auto lhs_lift_mapper = std::unique_ptr<::bfv::math::rq::BasisMapper>();
  auto rhs_lift_mapper = std::unique_ptr<::bfv::math::rq::BasisMapper>();
  auto main_to_aux_converter =
      std::unique_ptr<::bfv::math::rns::BaseConverter>();
#if defined(HEU_BFV_MUL_USE_AUX_BASE) && HEU_BFV_MUL_USE_AUX_BASE
  ::bfv::math::AuxiliaryLiftBackend aux_base_plan;
#endif
  const size_t base_q_size = base_ctx->moduli().size();
  size_t aux_size = 0;

#if defined(HEU_BFV_MUL_USE_AUX_BASE) && HEU_BFV_MUL_USE_AUX_BASE
  try {
    aux_base_plan = ::bfv::math::BuildAuxiliaryLiftBackend(base_ctx, mul_ctx);
  } catch (const std::runtime_error &err) {
    throw ParameterException(err.what());
  }
  aux_size = aux_base_plan.converters.aux_size;
  main_to_aux_converter =
      std::move(aux_base_plan.converters.main_to_aux_converter);
#else
  lhs_lift_mapper = ::bfv::math::rq::BasisMapper::create(base_ctx, mul_ctx,
                                                         lhs_scaling_factor);
  rhs_lift_mapper = ::bfv::math::rq::BasisMapper::create(base_ctx, mul_ctx,
                                                         rhs_scaling_factor);
  aux_size = mul_ctx->moduli().size() - base_q_size;
#endif

  auto impl = std::make_unique<Impl>(
      std::move(parameters), std::move(lhs_lift_mapper),
      std::move(rhs_lift_mapper), std::move(post_mul_mapper),
      std::move(main_to_aux_converter), base_q_size, aux_size,
      std::move(base_ctx), std::move(mul_ctx), level);

#if defined(HEU_BFV_MUL_USE_AUX_BASE) && HEU_BFV_MUL_USE_AUX_BASE
  aux_base_plan.converters.main_to_aux_converter.reset();
  impl->aux_base_plan = std::move(aux_base_plan);
#endif

  return std::unique_ptr<Multiplicator>(new Multiplicator(std::move(impl)));
}

void Multiplicator::enable_relinearization(
    const RelinearizationKey &relinearization_key) {
  auto rk_ctx =
      pImpl->parameters->ctx_at_level(relinearization_key.ciphertext_level());
  if (*rk_ctx != *pImpl->base_ctx) {
    throw ParameterException(
        "Relinearization key does not match the active level");
  }
  pImpl->relinearization_key =
      std::make_unique<RelinearizationKey>(relinearization_key);
}

void Multiplicator::enable_mod_switching() {
  auto max_level_ctx =
      pImpl->parameters->ctx_at_level(pImpl->parameters->max_level());
  if (*max_level_ctx == *pImpl->base_ctx) {
    throw ParameterException(
        "Modulus switching is unavailable at the final level");
  }
  pImpl->mod_switch = true;
}

Ciphertext Multiplicator::multiply(const Ciphertext &lhs,
                                   const Ciphertext &rhs) const {
  PROFILE_BLOCK("Mul: Total");
  MultiplyProfile profile(heu_mul_profile_enabled());
  pImpl->validate_inputs(lhs, rhs);
  auto lifted = pImpl->lift_operands(lhs, rhs, profile);
  auto result_polys = pImpl->compute_downscaled_product(lifted, profile);
  pImpl->apply_relinearization(result_polys, profile);
  return pImpl->finalize_result(std::move(result_polys), profile);
}

std::shared_ptr<BfvParameters> Multiplicator::parameters() const {
  return pImpl->parameters;
}

size_t Multiplicator::level() const { return pImpl->level; }

bool Multiplicator::has_relinearization() const {
  return pImpl->relinearization_key != nullptr;
}

bool Multiplicator::has_mod_switching() const { return pImpl->mod_switch; }

bool Multiplicator::operator==(const Multiplicator &other) const {
  if (!pImpl || !other.pImpl) {
    return pImpl == other.pImpl;
  }

  auto mapper_ptr_eq = [](const auto &lhs_mapper, const auto &rhs_mapper) {
    if (!lhs_mapper || !rhs_mapper) {
      return lhs_mapper == rhs_mapper;
    }
    return *lhs_mapper == *rhs_mapper;
  };

  return *pImpl->parameters == *other.pImpl->parameters &&
         pImpl->level == other.pImpl->level &&
         pImpl->mod_switch == other.pImpl->mod_switch &&
         mapper_ptr_eq(pImpl->lhs_lift_mapper, other.pImpl->lhs_lift_mapper) &&
         mapper_ptr_eq(pImpl->rhs_lift_mapper, other.pImpl->rhs_lift_mapper) &&
         mapper_ptr_eq(pImpl->post_mul_mapper, other.pImpl->post_mul_mapper) &&
         *pImpl->base_ctx == *other.pImpl->base_ctx &&
         *pImpl->mul_ctx == *other.pImpl->mul_ctx;
}

bool Multiplicator::operator!=(const Multiplicator &other) const {
  return !(*this == other);
}

}  // namespace bfv
}  // namespace crypto
