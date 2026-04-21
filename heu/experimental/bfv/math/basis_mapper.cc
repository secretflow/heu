#include "math/basis_mapper.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <stdexcept>

#include "math/basis_transfer_route.h"
#include "math/context.h"
#include "math/poly.h"
#include "math/representation.h"
#include "math/scaling_factor.h"
#include "util/arena_allocator.h"

namespace bfv::math::rq {

namespace {

uint64_t *GetThreadLocalScratch(std::vector<uint64_t> &scratch, size_t needed) {
  if (scratch.size() < needed) {
    scratch.resize(needed);
  }
  return scratch.data();
}

using Clock = std::chrono::steady_clock;

inline bool heu_scale_multi_profile_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_SCALE_MULTI_PROFILE");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline bool heu_scale_multi_aux_base_per_poly_enabled() {
  static const bool enabled = [] {
    const char *disable_env =
        std::getenv("HEU_BFV_DISABLE_SCALE_MULTI_AUX_BASE_PER_POLY");
    if (disable_env && disable_env[0] != '\0' && disable_env[0] != '0') {
      return false;
    }
    return true;
  }();
  return enabled;
}

inline int64_t micros_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
      .count();
}

}  // namespace

struct BatchMapGeometry {
  size_t num_polys = 0;
  size_t source_moduli_count = 0;
  size_t target_moduli_count = 0;
  size_t degree = 0;
  size_t prefix_passthrough_count = 0;
  size_t output_moduli_count = 0;
  size_t packed_coeff_count = 0;
};

struct BatchMapProfile {
  bool enabled = false;
  Clock::time_point total_begin{};
  int64_t t_prepare_results_us = 0;
  int64_t t_copy_common_us = 0;
  int64_t t_scale_batch_us = 0;

  explicit BatchMapProfile(bool profile_enabled)
      : enabled(profile_enabled),
        total_begin(profile_enabled ? Clock::now() : Clock::time_point{}) {}

  void emit(const char *mode, size_t num_polys) const {
    if (!enabled) {
      return;
    }
    const auto total_us = micros_between(total_begin, Clock::now());
    std::cerr << "[HEU_SCALE_MULTI_PROFILE] mode=" << mode
              << " num_polys=" << num_polys
              << " prepare_results_us=" << t_prepare_results_us
              << " copy_common_us=" << t_copy_common_us
              << " scale_batch_us=" << t_scale_batch_us
              << " total_us=" << total_us << '\n';
  }
};

/**
 * @brief Implementation class for BasisMapper using PIMPL pattern.
 */
class BasisMapper::Impl {
 public:
  std::shared_ptr<const Context> source_ctx;
  std::shared_ptr<const Context> target_ctx;
  internal::BasisTransferRoute transfer_route;

  /**
   * @brief Constructor for BasisMapper::Impl.
   */
  Impl(std::shared_ptr<const Context> from_ctx,
       std::shared_ptr<const Context> to_ctx,
       const ::bfv::math::rns::ScalingFactor &factor)
      : source_ctx(std::move(from_ctx)),
        target_ctx(std::move(to_ctx)),
        transfer_route(source_ctx, target_ctx, factor) {}

  Representation normalize_representation(Representation representation) const;
  void validate_source_context(const Poly &poly) const;
  void validate_batch_inputs(const std::vector<const Poly *> &polys) const;
  BatchMapGeometry describe_batch(size_t num_polys) const;
  Poly allocate_result_poly(Representation representation) const;
  void copy_prefix_moduli(const Poly &poly, Poly &result,
                          size_t prefix_passthrough_count) const;
  void prepare_results(const std::vector<const Poly *> &polys,
                       Representation representation,
                       std::vector<Poly> &results,
                       BatchMapProfile &profile) const;
  void copy_prefix_batch(const std::vector<const Poly *> &polys,
                         std::vector<Poly> &results,
                         const BatchMapGeometry &shape,
                         BatchMapProfile &profile) const;
  void materialize_single_inputs(
      const Poly &poly, std::vector<const uint64_t *> &input_ptrs,
      ::bfv::util::Pointer<uint64_t> &temp_buffer) const;
  void pack_batch_inputs(const std::vector<const Poly *> &polys,
                         const BatchMapGeometry &shape, bool need_backward,
                         uint64_t *input_buf,
                         std::vector<const uint64_t *> &input_ptrs) const;
  void scatter_batch_outputs(std::vector<Poly> &results,
                             const BatchMapGeometry &shape,
                             const std::vector<uint64_t *> &output_ptrs) const;
  void restore_target_representation(std::vector<Poly> &results,
                                     const BatchMapGeometry &shape,
                                     bool need_backward) const;
};

Representation BasisMapper::Impl::normalize_representation(
    Representation representation) const {
  if (representation == Representation::NttShoup) {
    return Representation::Ntt;
  }
  return representation;
}

void BasisMapper::Impl::validate_source_context(const Poly &poly) const {
  if (*poly.ctx() != *source_ctx) {
    throw std::runtime_error(
        "Input polynomial context does not match the mapper source context");
  }
}

void BasisMapper::Impl::validate_batch_inputs(
    const std::vector<const Poly *> &polys) const {
  if (!polys[0]) {
    throw std::runtime_error("Null polynomial pointer");
  }

  const auto *first_poly = polys[0];
  if (*first_poly->ctx() != *source_ctx) {
    throw std::runtime_error(
        "Input polynomials do not have the correct context");
  }

  for (const auto *poly : polys) {
    if (!poly) {
      throw std::runtime_error("Null polynomial pointer");
    }
    if (*poly->ctx() != *first_poly->ctx()) {
      throw std::runtime_error("All polynomials must have the same context");
    }
    if (poly->representation() != first_poly->representation()) {
      throw std::runtime_error(
          "All polynomials must have the same representation");
    }
  }
}

BatchMapGeometry BasisMapper::Impl::describe_batch(size_t num_polys) const {
  BatchMapGeometry shape;
  shape.num_polys = num_polys;
  shape.source_moduli_count = source_ctx->moduli().size();
  shape.target_moduli_count = target_ctx->moduli().size();
  shape.degree = source_ctx->degree();
  shape.prefix_passthrough_count = transfer_route.prefix_passthrough_count();
  shape.output_moduli_count =
      shape.target_moduli_count - shape.prefix_passthrough_count;
  shape.packed_coeff_count = shape.degree * shape.num_polys;
  return shape;
}

Poly BasisMapper::Impl::allocate_result_poly(
    Representation representation) const {
  return Poly::uninitialized(target_ctx, representation);
}

void BasisMapper::Impl::copy_prefix_moduli(
    const Poly &poly, Poly &result, size_t prefix_passthrough_count) const {
  if (prefix_passthrough_count == 0) {
    return;
  }

  const size_t degree = source_ctx->degree();
  for (size_t i = 0; i < prefix_passthrough_count; ++i) {
    std::copy_n(poly.data(i), degree, result.data(i));
  }
}

void BasisMapper::Impl::prepare_results(const std::vector<const Poly *> &polys,
                                        Representation representation,
                                        std::vector<Poly> &results,
                                        BatchMapProfile &profile) const {
  const auto begin = profile.enabled ? Clock::now() : Clock::time_point{};
  if (results.size() != polys.size()) {
    results.resize(polys.size());
  }
  for (size_t i = 0; i < polys.size(); ++i) {
    if (results[i].ctx() != target_ctx ||
        results[i].representation() != representation) {
      results[i] = allocate_result_poly(representation);
    }
    if (polys[i]->allows_variable_time_computations()) {
      results[i].allow_variable_time_computations();
    } else {
      results[i].disallow_variable_time_computations();
    }
  }
  if (profile.enabled) {
    profile.t_prepare_results_us += micros_between(begin, Clock::now());
  }
}

void BasisMapper::Impl::copy_prefix_batch(
    const std::vector<const Poly *> &polys, std::vector<Poly> &results,
    const BatchMapGeometry &shape, BatchMapProfile &profile) const {
  if (shape.prefix_passthrough_count == 0) {
    return;
  }

  const auto begin = profile.enabled ? Clock::now() : Clock::time_point{};
  for (size_t poly_idx = 0; poly_idx < shape.num_polys; ++poly_idx) {
    for (size_t mod_idx = 0; mod_idx < shape.prefix_passthrough_count;
         ++mod_idx) {
      std::copy_n(polys[poly_idx]->data(mod_idx), shape.degree,
                  results[poly_idx].data(mod_idx));
    }
  }
  if (profile.enabled) {
    profile.t_copy_common_us += micros_between(begin, Clock::now());
  }
}

void BasisMapper::Impl::materialize_single_inputs(
    const Poly &poly, std::vector<const uint64_t *> &input_ptrs,
    ::bfv::util::Pointer<uint64_t> &temp_buffer) const {
  input_ptrs.resize(source_ctx->moduli().size());
  if (poly.representation() == Representation::PowerBasis) {
    for (size_t i = 0; i < source_ctx->moduli().size(); ++i) {
      input_ptrs[i] = poly.data(i);
    }
    return;
  }

  auto arena = ::bfv::util::ArenaHandle::Shared();
  temp_buffer = arena.allocate<uint64_t>(source_ctx->moduli().size() *
                                         source_ctx->degree());
  const auto &ops = source_ctx->ops();
  for (size_t i = 0; i < source_ctx->moduli().size(); ++i) {
    uint64_t *chunk = temp_buffer.get() + i * source_ctx->degree();
    std::copy_n(poly.data(i), source_ctx->degree(), chunk);
    ops[i].BackwardInPlace(chunk);
    input_ptrs[i] = chunk;
  }
}

void BasisMapper::Impl::pack_batch_inputs(
    const std::vector<const Poly *> &polys, const BatchMapGeometry &shape,
    bool need_backward, uint64_t *input_buf,
    std::vector<const uint64_t *> &input_ptrs) const {
  input_ptrs.resize(shape.source_moduli_count);
  const auto &source_ops = source_ctx->ops();
  for (size_t mod_idx = 0; mod_idx < shape.source_moduli_count; ++mod_idx) {
    uint64_t *base = input_buf + mod_idx * shape.packed_coeff_count;
    input_ptrs[mod_idx] = base;
    for (size_t poly_idx = 0; poly_idx < shape.num_polys; ++poly_idx) {
      uint64_t *dst = base + poly_idx * shape.degree;
      std::copy_n(polys[poly_idx]->data(mod_idx), shape.degree, dst);
      if (need_backward) {
        source_ops[mod_idx].BackwardInPlace(dst);
      }
    }
  }
}

void BasisMapper::Impl::scatter_batch_outputs(
    std::vector<Poly> &results, const BatchMapGeometry &shape,
    const std::vector<uint64_t *> &output_ptrs) const {
  for (size_t poly_idx = 0; poly_idx < shape.num_polys; ++poly_idx) {
    for (size_t out_idx = 0; out_idx < shape.output_moduli_count; ++out_idx) {
      const uint64_t *src = output_ptrs[out_idx] + poly_idx * shape.degree;
      uint64_t *dst =
          results[poly_idx].data(shape.prefix_passthrough_count + out_idx);
      std::copy_n(src, shape.degree, dst);
    }
  }
}

void BasisMapper::Impl::restore_target_representation(
    std::vector<Poly> &results, const BatchMapGeometry &shape,
    bool need_backward) const {
  if (!need_backward) {
    return;
  }

  const auto &target_ops = target_ctx->ops();
  for (size_t mod_idx = shape.prefix_passthrough_count;
       mod_idx < shape.target_moduli_count; ++mod_idx) {
    for (size_t poly_idx = 0; poly_idx < shape.num_polys; ++poly_idx) {
      target_ops[mod_idx].ForwardInPlace(results[poly_idx].data(mod_idx));
    }
  }
}

std::unique_ptr<BasisMapper> BasisMapper::create(
    std::shared_ptr<const Context> from, std::shared_ptr<const Context> to,
    const ::bfv::math::rns::ScalingFactor &factor) {
  auto impl = std::make_unique<Impl>(std::move(from), std::move(to), factor);
  return std::unique_ptr<BasisMapper>(new BasisMapper(std::move(impl)));
}

BasisMapper::BasisMapper(std::unique_ptr<Impl> impl)
    : pimpl_(std::move(impl)) {}

BasisMapper::~BasisMapper() = default;

BasisMapper::BasisMapper(BasisMapper &&) noexcept = default;
BasisMapper &BasisMapper::operator=(BasisMapper &&) noexcept = default;

Poly BasisMapper::map(const Poly &poly) const {
  pimpl_->validate_source_context(poly);
  const auto representation =
      pimpl_->normalize_representation(poly.representation());
  const auto shape = pimpl_->describe_batch(1);
  Poly result = pimpl_->allocate_result_poly(representation);
  pimpl_->copy_prefix_moduli(poly, result, shape.prefix_passthrough_count);

  if (!pimpl_->transfer_route.has_transfer_backend()) {
    return result;
  }

  std::vector<const uint64_t *> input_ptrs;
  ::bfv::util::Pointer<uint64_t> temp_buffer;
  pimpl_->materialize_single_inputs(poly, input_ptrs, temp_buffer);

  std::vector<uint64_t *> output_ptrs(shape.output_moduli_count);
  for (size_t i = 0; i < shape.output_moduli_count; ++i) {
    output_ptrs[i] = result.data(shape.prefix_passthrough_count + i);
  }

  pimpl_->transfer_route.scale_batch(input_ptrs, output_ptrs, shape.degree,
                                     ::bfv::util::ArenaHandle::Shared());

  if (poly.representation() != Representation::PowerBasis) {
    const auto &target_ops = pimpl_->target_ctx->ops();
    for (size_t mod_idx = shape.prefix_passthrough_count;
         mod_idx < shape.target_moduli_count; ++mod_idx) {
      target_ops[mod_idx].ForwardInPlace(result.data(mod_idx));
    }
  }
  return result;
}

void BasisMapper::write_power_basis_u64(const Poly &poly, uint64_t *out) const {
  if (!out) {
    throw std::invalid_argument(
        "BasisMapper::write_power_basis_u64: null output");
  }
  if (*poly.ctx() != *pimpl_->source_ctx) {
    throw std::runtime_error(
        "Input polynomial context does not match the mapper source context");
  }
  if (poly.representation() != Representation::PowerBasis) {
    throw std::runtime_error(
        "BasisMapper::write_power_basis_u64 requires PowerBasis input");
  }

  const size_t degree = pimpl_->source_ctx->degree();
  const size_t target_moduli_count = pimpl_->target_ctx->moduli().size();
  const size_t prefix_passthrough_count =
      pimpl_->transfer_route.prefix_passthrough_count();

  for (size_t i = 0; i < prefix_passthrough_count; ++i) {
    std::copy_n(poly.data(i), degree, out + i * degree);
  }

  if (prefix_passthrough_count == target_moduli_count) {
    return;
  }

  const size_t source_moduli_count = pimpl_->source_ctx->moduli().size();
  thread_local std::vector<const uint64_t *> tl_input_ptrs;
  tl_input_ptrs.resize(source_moduli_count);
  for (size_t i = 0; i < source_moduli_count; ++i) {
    tl_input_ptrs[i] = poly.data(i);
  }

  const size_t output_moduli_count =
      target_moduli_count - prefix_passthrough_count;
  thread_local std::vector<uint64_t *> tl_output_ptrs;
  tl_output_ptrs.resize(output_moduli_count);
  for (size_t i = 0; i < output_moduli_count; ++i) {
    tl_output_ptrs[i] = out + (prefix_passthrough_count + i) * degree;
  }

  pimpl_->transfer_route.scale_batch(tl_input_ptrs, tl_output_ptrs, degree,
                                     ::bfv::util::ArenaHandle::Shared());
}

bool BasisMapper::operator==(const BasisMapper &other) const {
  return pimpl_->source_ctx == other.pimpl_->source_ctx &&
         pimpl_->target_ctx == other.pimpl_->target_ctx &&
         pimpl_->transfer_route.prefix_passthrough_count() ==
             other.pimpl_->transfer_route.prefix_passthrough_count();
}

bool BasisMapper::operator!=(const BasisMapper &other) const {
  return !(*this == other);
}

std::vector<Poly> BasisMapper::map_many(const std::vector<Poly> &polys) const {
  std::vector<Poly> out;
  map_many_into(polys, out);
  return out;
}

void BasisMapper::map_many_into(const std::vector<Poly> &polys,
                                std::vector<Poly> &out) const {
  std::vector<const Poly *> ptrs;
  ptrs.reserve(polys.size());
  for (const auto &poly : polys) {
    ptrs.push_back(&poly);
  }
  map_many_into(ptrs, out);
}

std::vector<Poly> BasisMapper::map_many(
    const std::vector<const Poly *> &polys) const {
  std::vector<Poly> out;
  map_many_into(polys, out);
  return out;
}

void BasisMapper::map_many_into(const std::vector<const Poly *> &polys,
                                std::vector<Poly> &results) const {
  if (polys.empty()) {
    results.clear();
    return;
  }
  if (polys.size() == 1) {
    if (results.size() != 1) {
      results.resize(1);
    }
    results[0] = map(*polys[0]);
    return;
  }
  pimpl_->validate_batch_inputs(polys);
  const auto *first_poly = polys[0];
  const auto representation =
      pimpl_->normalize_representation(first_poly->representation());
  const auto shape = pimpl_->describe_batch(polys.size());
  BatchMapProfile profile(heu_scale_multi_profile_enabled());

  pimpl_->prepare_results(polys, representation, results, profile);
  pimpl_->copy_prefix_batch(polys, results, shape, profile);

  if (shape.prefix_passthrough_count == shape.target_moduli_count) {
    return;
  }

  auto arena = ::bfv::util::ArenaHandle::Shared();

  if (first_poly->representation() == Representation::PowerBasis) {
#if defined(HEU_BFV_MUL_USE_AUX_BASE) && HEU_BFV_MUL_USE_AUX_BASE
    if (pimpl_->transfer_route.uses_aux_base_multiply_path() &&
        heu_scale_multi_aux_base_per_poly_enabled()) {
      std::vector<const uint64_t *> input_ptrs(shape.source_moduli_count);
      std::vector<uint64_t *> output_ptrs(shape.output_moduli_count);
      const auto scale_begin =
          profile.enabled ? Clock::now() : Clock::time_point{};
      for (size_t poly_idx = 0; poly_idx < shape.num_polys; ++poly_idx) {
        for (size_t mod_idx = 0; mod_idx < shape.source_moduli_count;
             ++mod_idx) {
          input_ptrs[mod_idx] = polys[poly_idx]->data(mod_idx);
        }
        for (size_t out_idx = 0; out_idx < shape.output_moduli_count;
             ++out_idx) {
          output_ptrs[out_idx] =
              results[poly_idx].data(shape.prefix_passthrough_count + out_idx);
        }
        pimpl_->transfer_route.scale_batch(input_ptrs, output_ptrs,
                                           shape.degree, arena);
      }
      if (profile.enabled) {
        profile.t_scale_batch_us += micros_between(scale_begin, Clock::now());
      }
      profile.emit("aux_base_power", shape.num_polys);
      return;
    }
#endif

    thread_local std::vector<uint64_t> tl_input_buf;
    uint64_t *input_buf = GetThreadLocalScratch(
        tl_input_buf, shape.source_moduli_count * shape.packed_coeff_count);
    std::vector<const uint64_t *> input_ptrs;
    pimpl_->pack_batch_inputs(polys, shape, false, input_buf, input_ptrs);

    thread_local std::vector<uint64_t> tl_output_buf;
    uint64_t *output_buf = GetThreadLocalScratch(
        tl_output_buf, shape.output_moduli_count * shape.packed_coeff_count);
    std::vector<uint64_t *> output_ptrs(shape.output_moduli_count);
    for (size_t i = 0; i < shape.output_moduli_count; ++i) {
      output_ptrs[i] = output_buf + i * shape.packed_coeff_count;
    }

    const auto scale_begin =
        profile.enabled ? Clock::now() : Clock::time_point{};
    pimpl_->transfer_route.scale_batch(input_ptrs, output_ptrs,
                                       shape.packed_coeff_count, arena);
    if (profile.enabled) {
      profile.t_scale_batch_us += micros_between(scale_begin, Clock::now());
    }

    pimpl_->scatter_batch_outputs(results, shape, output_ptrs);
    return;
  }

  const bool need_backward = true;
  thread_local std::vector<uint64_t> tl_input_buf;
  uint64_t *input_buf = GetThreadLocalScratch(
      tl_input_buf, shape.source_moduli_count * shape.packed_coeff_count);
  std::vector<const uint64_t *> input_ptrs;
  pimpl_->pack_batch_inputs(polys, shape, need_backward, input_buf, input_ptrs);

  thread_local std::vector<uint64_t> tl_output_buf;
  uint64_t *output_buf = GetThreadLocalScratch(
      tl_output_buf, shape.output_moduli_count * shape.packed_coeff_count);
  std::vector<uint64_t *> output_ptrs(shape.output_moduli_count);
  for (size_t i = 0; i < shape.output_moduli_count; ++i) {
    output_ptrs[i] = output_buf + i * shape.packed_coeff_count;
  }

  const auto scale_begin = profile.enabled ? Clock::now() : Clock::time_point{};
  pimpl_->transfer_route.scale_batch(input_ptrs, output_ptrs,
                                     shape.packed_coeff_count, arena);
  if (profile.enabled) {
    profile.t_scale_batch_us += micros_between(scale_begin, Clock::now());
  }

  pimpl_->scatter_batch_outputs(results, shape, output_ptrs);
  pimpl_->restore_target_representation(results, shape, need_backward);
  profile.emit("generic_ntt", shape.num_polys);
}

}  // namespace bfv::math::rq
