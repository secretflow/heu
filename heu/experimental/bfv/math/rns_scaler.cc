#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <ostream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include "math/base_converter.h"
#include "math/biguint.h"
#include "math/modulus.h"
#include "math/primes.h"
#include "math/residue_transfer_engine.h"
#include "math/rns_context.h"
#include "math/rns_transfer_backend.h"
#include "math/rns_transfer_plan.h"
#include "math/scaling_factor.h"
#include "math/shenoy_kumaresan.h"

namespace bfv {
namespace math {
namespace rns {
namespace {
using Clock = std::chrono::steady_clock;

#if defined(HEU_BFV_MUL_USE_AUX_BASE) && HEU_BFV_MUL_USE_AUX_BASE
constexpr bool kUseCompiledAuxBaseMul = true;
#else
constexpr bool kUseCompiledAuxBaseMul = false;
#endif

inline bool heu_scale_profile_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_SCALE_PROFILE");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline int64_t micros_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
      .count();
}

// Inline helpers for 128-bit arithmetic using Barrett constants
static inline uint64_t mul64_high(uint64_t x, uint64_t y) {
  return (uint64_t)((unsigned __int128)x * y >> 64);
}

static inline void mul64_128(uint64_t x, uint64_t y, uint64_t &lo,
                             uint64_t &hi) {
  unsigned __int128 p = (unsigned __int128)x * y;
  lo = (uint64_t)p;
  hi = (uint64_t)(p >> 64);
}

static inline uint64_t add64_carry(uint64_t x, uint64_t y, uint64_t &out) {
  unsigned __int128 s = (unsigned __int128)x + y;
  out = (uint64_t)s;
  return (uint64_t)(s >> 64);
}

static inline uint64_t cond_sub(uint64_t r, uint64_t p) {
  uint64_t mask = -(uint64_t)(r >= p);
  return r - (p & mask);
}

static inline uint64_t reduce_u128_inline(unsigned __int128 a,
                                          const zq::BarrettConstants &barrett) {
  const uint64_t p = barrett.value;
  const uint64_t ratio0 = barrett.barrett_lo;
  const uint64_t ratio1 = barrett.barrett_hi;

  const uint64_t a_lo = (uint64_t)a;
  const uint64_t a_hi = (uint64_t)(a >> 64);

  const uint64_t p_lo_lo_hi = mul64_high(a_lo, ratio0);
  const unsigned __int128 p_hi_lo = (unsigned __int128)a_hi * ratio0;
  const unsigned __int128 p_lo_hi = (unsigned __int128)a_lo * ratio1;

  const unsigned __int128 q_hat = ((p_lo_hi + p_hi_lo + p_lo_lo_hi) >> 64) +
                                  (unsigned __int128)a_hi * ratio1;
  const uint64_t r = (uint64_t)(a - q_hat * p);

  return cond_sub(r, p);
}

static inline uint64_t lazy_mul_shoup_inline(uint64_t a, uint64_t b,
                                             uint64_t b_shoup, uint64_t p) {
  unsigned __int128 product = (unsigned __int128)a * b;
  uint64_t q = (uint64_t)(((unsigned __int128)a * b_shoup) >> 64);
  return (uint64_t)(product - (unsigned __int128)q * p);
}
}  // namespace

std::ostream &operator<<(std::ostream &os, __uint128_t val) {
  if (val == 0) return os << "0";
  std::string s;
  while (val > 0) {
    s.push_back('0' + (val % 10));
    val /= 10;
  }
  std::reverse(s.begin(), s.end());
  return os << s;
}

// High-performance 256-bit unsigned integer implementation
// Optimized for RNS scaling operations with minimal overhead
// Optimized 256-bit unsigned integer implementation
struct alignas(32) U256 {
  // Store as four 64-bit words: [low, mid_low, mid_high, high]
  uint64_t words[4];

  constexpr U256() noexcept : words{0, 0, 0, 0} {}

  explicit constexpr U256(uint64_t v) noexcept : words{v, 0, 0, 0} {}

  explicit constexpr U256(__uint128_t v) noexcept
      : words{static_cast<uint64_t>(v), static_cast<uint64_t>(v >> 64), 0, 0} {}

  // Optimized wrapping addition with better branch prediction
  inline U256 &wrapping_add(const U256 &other) noexcept {
    uint64_t carry = 0;
    // Unroll loop for better performance
    __uint128_t sum0 = static_cast<__uint128_t>(words[0]) + other.words[0];
    words[0] = static_cast<uint64_t>(sum0);
    carry = static_cast<uint64_t>(sum0 >> 64);

    __uint128_t sum1 =
        static_cast<__uint128_t>(words[1]) + other.words[1] + carry;
    words[1] = static_cast<uint64_t>(sum1);
    carry = static_cast<uint64_t>(sum1 >> 64);

    __uint128_t sum2 =
        static_cast<__uint128_t>(words[2]) + other.words[2] + carry;
    words[2] = static_cast<uint64_t>(sum2);
    carry = static_cast<uint64_t>(sum2 >> 64);

    __uint128_t sum3 =
        static_cast<__uint128_t>(words[3]) + other.words[3] + carry;
    words[3] = static_cast<uint64_t>(sum3);

    return *this;
  }

  // Optimized wrapping subtraction
  inline U256 &wrapping_sub(const U256 &other) noexcept {
    uint64_t borrow = 0;
    // Unroll loop for better performance
    __uint128_t diff0 = static_cast<__uint128_t>(words[0]) - other.words[0];
    words[0] = static_cast<uint64_t>(diff0);
    borrow = (diff0 >> 127) & 1;

    __uint128_t diff1 =
        static_cast<__uint128_t>(words[1]) - other.words[1] - borrow;
    words[1] = static_cast<uint64_t>(diff1);
    borrow = (diff1 >> 127) & 1;

    __uint128_t diff2 =
        static_cast<__uint128_t>(words[2]) - other.words[2] - borrow;
    words[2] = static_cast<uint64_t>(diff2);
    borrow = (diff2 >> 127) & 1;

    __uint128_t diff3 =
        static_cast<__uint128_t>(words[3]) - other.words[3] - borrow;
    words[3] = static_cast<uint64_t>(diff3);

    return *this;
  }

  // Highly optimized multiplication for U256 * U256 (wrapping)
  U256 operator*(const U256 &other) const noexcept {
    U256 result;

    // Use schoolbook multiplication with optimized inner loops
    // Only compute the lower 256 bits (wrapping multiplication)
    __uint128_t prod, carry;

    // i=0 row
    prod = static_cast<__uint128_t>(words[0]) * other.words[0];
    result.words[0] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[0]) * other.words[1] + carry;
    result.words[1] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[0]) * other.words[2] + carry;
    result.words[2] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[0]) * other.words[3] + carry;
    result.words[3] = static_cast<uint64_t>(prod);

    // i=1 row
    prod =
        static_cast<__uint128_t>(words[1]) * other.words[0] + result.words[1];
    result.words[1] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[1]) * other.words[1] +
           result.words[2] + carry;
    result.words[2] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[1]) * other.words[2] +
           result.words[3] + carry;
    result.words[3] = static_cast<uint64_t>(prod);

    // i=2 row
    prod =
        static_cast<__uint128_t>(words[2]) * other.words[0] + result.words[2];
    result.words[2] = static_cast<uint64_t>(prod);
    carry = prod >> 64;

    prod = static_cast<__uint128_t>(words[2]) * other.words[1] +
           result.words[3] + carry;
    result.words[3] = static_cast<uint64_t>(prod);

    // i=3 row
    prod =
        static_cast<__uint128_t>(words[3]) * other.words[0] + result.words[3];
    result.words[3] = static_cast<uint64_t>(prod);

    return result;
  }

  // Optimized right shift with better branch prediction
  inline U256 &operator>>=(size_t shift) noexcept {
    if (shift == 0) return *this;
    if (shift >= 256) {
      words[0] = words[1] = words[2] = words[3] = 0;
      return *this;
    }

    const size_t word_shift = shift / 64;
    const size_t bit_shift = shift % 64;

    if (word_shift > 0) {
      // Shift by whole words
      switch (word_shift) {
        case 1:
          words[0] = words[1];
          words[1] = words[2];
          words[2] = words[3];
          words[3] = 0;
          break;
        case 2:
          words[0] = words[2];
          words[1] = words[3];
          words[2] = words[3] = 0;
          break;
        case 3:
          words[0] = words[3];
          words[1] = words[2] = words[3] = 0;
          break;
        default:
          words[0] = words[1] = words[2] = words[3] = 0;
          break;
      }
    }

    if (bit_shift > 0) {
      const size_t left_shift = 64 - bit_shift;
      words[0] = (words[0] >> bit_shift) | (words[1] << left_shift);
      words[1] = (words[1] >> bit_shift) | (words[2] << left_shift);
      words[2] = (words[2] >> bit_shift) | (words[3] << left_shift);
      words[3] >>= bit_shift;
    }

    return *this;
  }

  inline U256 operator>>(size_t shift) const noexcept {
    U256 result = *this;
    result >>= shift;
    return result;
  }

  // Fast bitwise NOT
  inline U256 operator~() const noexcept {
    U256 result;
    result.words[0] = ~words[0];
    result.words[1] = ~words[1];
    result.words[2] = ~words[2];
    result.words[3] = ~words[3];
    return result;
  }

  // Fast comparison
  inline bool operator>(const U256 &other) const noexcept {
    if (words[3] != other.words[3]) return words[3] > other.words[3];
    if (words[2] != other.words[2]) return words[2] > other.words[2];
    if (words[1] != other.words[1]) return words[1] > other.words[1];
    return words[0] > other.words[0];
  }

  // Extract lower 128 bits efficiently
  inline __uint128_t as_u128() const noexcept {
    return static_cast<__uint128_t>(words[0]) |
           (static_cast<__uint128_t>(words[1]) << 64);
  }
};

class ResidueTransferEngine::Impl {
 public:
  using TransferKernelCache = internal::TransferKernelCache;

  struct AuxBaseScaleCache {
    bool ready = false;
    size_t base_q_size = 0;
    size_t aux_size = 0;
    size_t aux_body_size = 0;
    std::shared_ptr<RnsContext> aux_body_ctx;
    std::shared_ptr<RnsContext> aux_basis_ctx;
    std::shared_ptr<RnsContext> correction_ctx;
    std::shared_ptr<RnsContext> base_q_correction_ctx;
    std::unique_ptr<BaseConverter> main_to_aux_converter;
    std::unique_ptr<BaseConverter> aux_body_to_main_correction_conv;
    std::vector<uint64_t> inv_prod_q_mod_aux_basis;
    std::vector<uint64_t> inv_prod_q_mod_aux_basis_shoup;
    std::vector<uint64_t> prod_aux_body_mod_q;
    std::vector<uint64_t> prod_aux_body_mod_q_shoup;
    std::vector<uint64_t> neg_prod_aux_body_mod_q;
    std::vector<uint64_t> neg_prod_aux_body_mod_q_shoup;
    uint64_t inv_prod_aux_body_mod_correction = 0;
    uint64_t inv_prod_aux_body_mod_correction_shoup = 0;
    uint64_t correction_modulus = 0;
    uint64_t correction_modulus_div_2 = 0;
    std::vector<uint64_t> scale_factor_mod_from;
    std::vector<uint64_t> scale_factor_mod_from_shoup;
  };

  std::shared_ptr<RnsContext> from;
  std::shared_ptr<RnsContext> to;
  ScalingFactor scaling_factor;
  RnsScalingScheme active_scaling_scheme;
  TransferKernelCache transfer_kernel;
  std::unique_ptr<internal::ResidueTransferBackend> residue_transfer_backend;
  AuxBaseScaleCache aux_base_scale;

  Impl(const std::shared_ptr<RnsContext> &f,
       const std::shared_ptr<RnsContext> &t, const ScalingFactor &sf);

  bool can_enable_aux_base_backend() const;

  void init_aux_base_backend();

  void scale_batch_aux_base(
      const std::vector<const uint64_t *> &input_moduli_ptrs,
      const std::vector<uint64_t *> &output_moduli_ptrs, size_t count,
      ArenaHandle pool) const;

  void scale_batch_aux_base_impl(
      const std::vector<const uint64_t *> &input_moduli_ptrs,
      const std::vector<uint64_t *> &output_moduli_ptrs, size_t count,
      bool input_pre_scaled, ArenaHandle pool) const;
};

ResidueTransferEngine::Impl::Impl(const std::shared_ptr<RnsContext> &f,
                                  const std::shared_ptr<RnsContext> &t,
                                  const ScalingFactor &sf)
    : from(f),
      to(t),
      scaling_factor(sf),
      active_scaling_scheme(RnsScalingScheme::ResidueTransfer) {
  transfer_kernel.projection_plan =
      internal::BuildTransferProjectionPlan(from, to, scaling_factor);
  transfer_kernel.carry_window_plan = internal::BuildCarryWindowPlan(from);
  transfer_kernel.decode_bridge = internal::BuildDecodeBridgeBackend(from, to);
  residue_transfer_backend = std::make_unique<internal::ResidueTransferBackend>(
      from, to, scaling_factor, transfer_kernel);

  if (kUseCompiledAuxBaseMul && can_enable_aux_base_backend()) {
    // The auxiliary-base backend is only valid for multiplication contexts.
    // Other scaling contexts stay on the projection path even in an aux-base
    // build.
    init_aux_base_backend();
    active_scaling_scheme = RnsScalingScheme::AuxBase;
  }
}

bool ResidueTransferEngine::Impl::can_enable_aux_base_backend() const {
  if (scaling_factor.is_one()) {
    return false;
  }

  const size_t local_base_q_size = to->moduli_u64().size();
  const auto &from_moduli = from->moduli_u64();
  const auto &to_moduli = to->moduli_u64();

  if (from_moduli.size() <= local_base_q_size) {
    return false;
  }
  if (from_moduli.size() - local_base_q_size < 2) {
    return false;
  }
  if (!(scaling_factor.denominator() == to->modulus())) {
    return false;
  }
  for (size_t i = 0; i < local_base_q_size; ++i) {
    if (from_moduli[i] != to_moduli[i]) {
      return false;
    }
  }
  return true;
}

void ResidueTransferEngine::Impl::init_aux_base_backend() {
  auto &base_q_size = aux_base_scale.base_q_size;
  auto &aux_size = aux_base_scale.aux_size;
  auto &aux_body_size = aux_base_scale.aux_body_size;
  auto &aux_body_ctx = aux_base_scale.aux_body_ctx;
  auto &aux_basis_ctx = aux_base_scale.aux_basis_ctx;
  auto &correction_ctx = aux_base_scale.correction_ctx;
  auto &base_q_correction_ctx = aux_base_scale.base_q_correction_ctx;
  auto &main_to_aux_converter = aux_base_scale.main_to_aux_converter;
  auto &aux_body_to_main_correction_conv =
      aux_base_scale.aux_body_to_main_correction_conv;
  auto &inv_prod_q_mod_aux_basis = aux_base_scale.inv_prod_q_mod_aux_basis;
  auto &inv_prod_q_mod_aux_basis_shoup =
      aux_base_scale.inv_prod_q_mod_aux_basis_shoup;
  auto &prod_aux_body_mod_q = aux_base_scale.prod_aux_body_mod_q;
  auto &prod_aux_body_mod_q_shoup = aux_base_scale.prod_aux_body_mod_q_shoup;
  auto &neg_prod_aux_body_mod_q = aux_base_scale.neg_prod_aux_body_mod_q;
  auto &neg_prod_aux_body_mod_q_shoup =
      aux_base_scale.neg_prod_aux_body_mod_q_shoup;
  auto &inv_prod_aux_body_mod_correction =
      aux_base_scale.inv_prod_aux_body_mod_correction;
  auto &inv_prod_aux_body_mod_correction_shoup =
      aux_base_scale.inv_prod_aux_body_mod_correction_shoup;
  auto &correction_modulus = aux_base_scale.correction_modulus;
  auto &correction_modulus_div_2 = aux_base_scale.correction_modulus_div_2;
  auto &scale_factor_mod_from = aux_base_scale.scale_factor_mod_from;
  auto &scale_factor_mod_from_shoup =
      aux_base_scale.scale_factor_mod_from_shoup;
  auto &aux_base_ready = aux_base_scale.ready;
  if (scaling_factor.is_one()) {
    throw std::runtime_error(
        "ResidueTransferEngine: auxiliary-base backend requires a non-trivial "
        "scaling factor");
  }

  base_q_size = to->moduli_u64().size();
  const auto &from_moduli = from->moduli_u64();
  const auto &to_moduli = to->moduli_u64();

  if (from_moduli.size() <= base_q_size) {
    throw std::runtime_error(
        "ResidueTransferEngine: auxiliary-base backend requires extra source "
        "moduli");
  }

  aux_size = from_moduli.size() - base_q_size;
  if (aux_size < 2) {
    throw std::runtime_error(
        "ResidueTransferEngine: auxiliary-base backend requires at least two "
        "auxiliary moduli");
  }
  aux_body_size = aux_size - 1;

  for (size_t i = 0; i < base_q_size; ++i) {
    if (from_moduli[i] != to_moduli[i]) {
      throw std::runtime_error(
          "ResidueTransferEngine: auxiliary-base backend requires target "
          "base-q as a source prefix");
    }
  }

  if (!(scaling_factor.denominator() == to->modulus())) {
    throw std::runtime_error(
        "ResidueTransferEngine: auxiliary-base backend requires scaling-factor "
        "denominator == Q");
  }

  correction_modulus = from_moduli.back();
  correction_modulus_div_2 = correction_modulus >> 1;

  std::vector<uint64_t> base_B_moduli(
      from_moduli.begin() + base_q_size,
      from_moduli.begin() + base_q_size + aux_body_size);
  std::vector<uint64_t> base_Bsk_moduli(from_moduli.begin() + base_q_size,
                                        from_moduli.end());

  aux_body_ctx = RnsContext::create(base_B_moduli);
  aux_basis_ctx = RnsContext::create(base_Bsk_moduli);
  correction_ctx =
      RnsContext::create(std::vector<uint64_t>{correction_modulus});
  std::vector<uint64_t> base_q_correction_moduli = to_moduli;
  base_q_correction_moduli.push_back(correction_modulus);
  base_q_correction_ctx = RnsContext::create(base_q_correction_moduli);

  main_to_aux_converter = std::make_unique<BaseConverter>(to, aux_basis_ctx);
  aux_body_to_main_correction_conv =
      std::make_unique<BaseConverter>(aux_body_ctx, base_q_correction_ctx);

  BigUint prod_q = to->modulus();
  BigUint prod_B = aux_body_ctx->modulus();

  // Precompute scaling factor modulus for each base in 'from'
  scale_factor_mod_from.resize(from_moduli.size());
  scale_factor_mod_from_shoup.resize(from_moduli.size());
  const BigUint &numerator = scaling_factor.numerator();
  for (size_t i = 0; i < from_moduli.size(); ++i) {
    scale_factor_mod_from[i] = (numerator % BigUint(from_moduli[i])).to_u64();
    scale_factor_mod_from_shoup[i] =
        from->moduli()[i].Shoup(scale_factor_mod_from[i]);
  }

  inv_prod_q_mod_aux_basis.resize(aux_size);
  inv_prod_q_mod_aux_basis_shoup.resize(aux_size);
  for (size_t i = 0; i < aux_size; ++i) {
    const auto &mod = aux_basis_ctx->moduli()[i];
    uint64_t prod_q_mod = (prod_q % BigUint(mod.P())).to_u64();
    auto inv_opt = mod.Inv(prod_q_mod);
    if (!inv_opt.has_value()) {
      throw std::runtime_error(
          "ResidueTransferEngine: failed to invert prod(q) in the auxiliary "
          "correction basis");
    }
    inv_prod_q_mod_aux_basis[i] = inv_opt.value();
    inv_prod_q_mod_aux_basis_shoup[i] = mod.Shoup(inv_prod_q_mod_aux_basis[i]);
  }

  prod_aux_body_mod_q.resize(base_q_size);
  prod_aux_body_mod_q_shoup.resize(base_q_size);
  neg_prod_aux_body_mod_q.resize(base_q_size);
  neg_prod_aux_body_mod_q_shoup.resize(base_q_size);
  for (size_t i = 0; i < base_q_size; ++i) {
    const auto &mod = to->moduli()[i];
    uint64_t prod_aux_body_mod = (prod_B % BigUint(mod.P())).to_u64();
    prod_aux_body_mod_q[i] = prod_aux_body_mod;
    prod_aux_body_mod_q_shoup[i] = mod.Shoup(prod_aux_body_mod);
    neg_prod_aux_body_mod_q[i] = mod.Neg(prod_aux_body_mod);
    neg_prod_aux_body_mod_q_shoup[i] = mod.Shoup(neg_prod_aux_body_mod_q[i]);
  }

  const auto &msk_mod = correction_ctx->moduli()[0];
  uint64_t prod_aux_body_mod_m =
      (prod_B % BigUint(correction_modulus)).to_u64();
  auto inv_opt = msk_mod.Inv(prod_aux_body_mod_m);
  if (!inv_opt.has_value()) {
    throw std::runtime_error(
        "ResidueTransferEngine: failed to invert prod(B) in the correction "
        "channel");
  }
  inv_prod_aux_body_mod_correction = inv_opt.value();
  inv_prod_aux_body_mod_correction_shoup =
      msk_mod.Shoup(inv_prod_aux_body_mod_correction);

  aux_base_ready = true;
}

void ResidueTransferEngine::Impl::scale_batch_aux_base(
    const std::vector<const uint64_t *> &input_moduli_ptrs,
    const std::vector<uint64_t *> &output_moduli_ptrs, size_t count,
    ArenaHandle pool) const {
  scale_batch_aux_base_impl(input_moduli_ptrs, output_moduli_ptrs, count, false,
                            pool);
}

void ResidueTransferEngine::Impl::scale_batch_aux_base_impl(
    const std::vector<const uint64_t *> &input_moduli_ptrs,
    const std::vector<uint64_t *> &output_moduli_ptrs, size_t count,
    bool input_pre_scaled, ArenaHandle pool) const {
  const auto &aux_base = aux_base_scale;
  const bool aux_base_ready = aux_base.ready;
  const size_t base_q_size = aux_base.base_q_size;
  const size_t aux_size = aux_base.aux_size;
  const size_t aux_body_size = aux_base.aux_body_size;
  const auto &aux_basis_ctx = aux_base.aux_basis_ctx;
  const auto &correction_ctx = aux_base.correction_ctx;
  const auto &main_to_aux_converter = aux_base.main_to_aux_converter;
  const auto &aux_body_to_main_correction_conv =
      aux_base.aux_body_to_main_correction_conv;
  const auto &inv_prod_q_mod_aux_basis = aux_base.inv_prod_q_mod_aux_basis;
  const auto &prod_aux_body_mod_q = aux_base.prod_aux_body_mod_q;
  const auto &neg_prod_aux_body_mod_q = aux_base.neg_prod_aux_body_mod_q;
  const uint64_t inv_prod_aux_body_mod_correction =
      aux_base.inv_prod_aux_body_mod_correction;
  const uint64_t correction_modulus = aux_base.correction_modulus;
  const uint64_t correction_modulus_div_2 = aux_base.correction_modulus_div_2;
  const auto &scale_factor_mod_from = aux_base.scale_factor_mod_from;
  (void)pool;
  const bool profile = heu_scale_profile_enabled();
  const auto total_begin_time = profile ? Clock::now() : Clock::time_point{};
  int64_t step6_multiply_us = 0;
  int64_t step7_convert_us = 0;
  int64_t step7_adjust_us = 0;
  int64_t step8_convert_us = 0;
  int64_t step8_correction_lane_us = 0;
  int64_t step8_shenoy_kumaresan_us = 0;

  if (!aux_base_ready) {
    throw std::runtime_error(
        "ResidueTransferEngine: auxiliary-base backend parameters are not "
        "initialized");
  }

  const size_t from_size = base_q_size + aux_size;
  if (input_moduli_ptrs.size() != from_size) {
    throw std::invalid_argument(
        "ResidueTransferEngine: auxiliary-base backend input size mismatch");
  }
  if (output_moduli_ptrs.size() != base_q_size) {
    throw std::invalid_argument(
        "ResidueTransferEngine: auxiliary-base backend output size mismatch");
  }
  if (count == 0) {
    return;
  }

  constexpr size_t kMaxBaseConverterSize = 32;
  if (from_size > kMaxBaseConverterSize || aux_size > kMaxBaseConverterSize ||
      aux_body_size > kMaxBaseConverterSize ||
      base_q_size + 1 > kMaxBaseConverterSize) {
    throw std::runtime_error(
        "ResidueTransferEngine: base size exceeds pointer cache bound");
  }

  // Scratch layout for the auxiliary-base scaling stages:
  // [ scaled_q | scaled_aux_input | aux_floor | correction_lane ]
  // [ q_size   | aux_size         | aux_size  | 1          ] * count
  const size_t q_offset = 0;
  const size_t scaled_bsk_offset = base_q_size * count;
  const size_t bsk_offset = scaled_bsk_offset + aux_size * count;
  const size_t correction_offset = bsk_offset + aux_size * count;
  const size_t total_alloc_size = correction_offset + count;

  // Reuse thread-local scratch buffer to eliminate per-call heap allocation
  thread_local std::vector<uint64_t> tl_aux_base_scratch;
  if (tl_aux_base_scratch.size() < total_alloc_size) {
    tl_aux_base_scratch.resize(total_alloc_size);
  }
  uint64_t *base_ptr = tl_aux_base_scratch.data();

  std::array<const uint64_t *, kMaxBaseConverterSize> q_base_input_ptrs{};
  std::array<const uint64_t *, kMaxBaseConverterSize> scaled_aux_input_ptrs{};
  if (input_pre_scaled) {
    for (size_t i = 0; i < base_q_size; ++i) {
      q_base_input_ptrs[i] = input_moduli_ptrs[i];
    }
    for (size_t i = 0; i < aux_size; ++i) {
      scaled_aux_input_ptrs[i] = input_moduli_ptrs[base_q_size + i];
    }
  } else {
    const auto step6_multiply_begin =
        profile ? Clock::now() : Clock::time_point{};
    for (size_t i = 0; i < base_q_size; ++i) {
      uint64_t *scaled_q = base_ptr + q_offset + i * count;
      q_base_input_ptrs[i] = scaled_q;
      from->moduli()[i].ScalarMulTo(scaled_q, input_moduli_ptrs[i], count,
                                    scale_factor_mod_from[i]);
    }
    for (size_t i = 0; i < aux_size; ++i) {
      uint64_t *scaled_bsk = base_ptr + scaled_bsk_offset + i * count;
      scaled_aux_input_ptrs[i] = scaled_bsk;
      from->moduli()[base_q_size + i].ScalarMulTo(
          scaled_bsk, input_moduli_ptrs[base_q_size + i], count,
          scale_factor_mod_from[base_q_size + i]);
    }
    if (profile) {
      step6_multiply_us = micros_between(step6_multiply_begin, Clock::now());
    }
  }

  // Stage 7: convert the q-side scratch into the auxiliary base and apply the
  // division-by-q correction inside that base.
  std::array<uint64_t *, kMaxBaseConverterSize> aux_floor_ptrs{};
  for (size_t i = 0; i < aux_size; ++i) {
    aux_floor_ptrs[i] = base_ptr + bsk_offset + i * count;
  }

  const auto step7_convert_begin = profile ? Clock::now() : Clock::time_point{};
  main_to_aux_converter->fast_convert_array(q_base_input_ptrs.data(),
                                            aux_floor_ptrs.data(), count);
  if (profile) {
    step7_convert_us = micros_between(step7_convert_begin, Clock::now());
  }

  const auto step7_adjust_begin = profile ? Clock::now() : Clock::time_point{};
  for (size_t i = 0; i < aux_size; ++i) {
    const auto &mod = aux_basis_ctx->moduli()[i];
    uint64_t *dest = aux_floor_ptrs[i];
    const uint64_t p = mod.P();
    const uint64_t *scaled_aux_input = scaled_aux_input_ptrs[i];
    const uint64_t inv = inv_prod_q_mod_aux_basis[i];
    const auto inv_operand = mod.PrepareMultiplyOperand(inv);

    for (size_t k = 0; k < count; ++k) {
      uint64_t term = scaled_aux_input[k] + (p - dest[k]);
      if (term >= p) term -= p;
      dest[k] = mod.MulOptimized(term, inv_operand);
    }
  }
  if (profile) {
    step7_adjust_us = micros_between(step7_adjust_begin, Clock::now());
  }

  // Stage 8: map the auxiliary-body residues back into the q base while
  // carrying the correction-channel residue lane.
  std::array<const uint64_t *, kMaxBaseConverterSize> aux_body_ptrs{};
  for (size_t i = 0; i < aux_body_size; ++i) {
    aux_body_ptrs[i] = aux_floor_ptrs[i];
  }

  uint64_t *correction_lane = base_ptr + correction_offset;
  std::array<uint64_t *, kMaxBaseConverterSize> q_correction_out_ptrs{};
  for (size_t i = 0; i < base_q_size; ++i) {
    q_correction_out_ptrs[i] = output_moduli_ptrs[i];
  }
  q_correction_out_ptrs[base_q_size] = correction_lane;
  const auto step8_convert_begin = profile ? Clock::now() : Clock::time_point{};
  aux_body_to_main_correction_conv->fast_convert_array(
      aux_body_ptrs.data(), q_correction_out_ptrs.data(), count);
  if (profile) {
    step8_convert_us = micros_between(step8_convert_begin, Clock::now());
  }
  const uint64_t *correction_input = aux_floor_ptrs[aux_body_size];
  const auto &msk_mod = correction_ctx->moduli()[0];
  const auto inv_correction_operand =
      msk_mod.PrepareMultiplyOperand(inv_prod_aux_body_mod_correction);
  const auto step8_correction_lane_begin =
      profile ? Clock::now() : Clock::time_point{};
  for (size_t k = 0; k < count; ++k) {
    uint64_t correction_delta =
        correction_lane[k] + (correction_modulus - correction_input[k]);
    correction_lane[k] =
        msk_mod.MulOptimized(correction_delta, inv_correction_operand);
  }
  if (profile) {
    step8_correction_lane_us =
        micros_between(step8_correction_lane_begin, Clock::now());
  }

  const auto step8_shenoy_kumaresan_begin =
      profile ? Clock::now() : Clock::time_point{};
  for (size_t i = 0; i < base_q_size; ++i) {
    const auto &qi = to->moduli()[i];
    uint64_t *output_q_coeffs = output_moduli_ptrs[i];
    const uint64_t prod = prod_aux_body_mod_q[i];
    const uint64_t neg_prod = neg_prod_aux_body_mod_q[i];
    const auto prod_operand = qi.PrepareMultiplyOperand(prod);
    const auto neg_prod_operand = qi.PrepareMultiplyOperand(neg_prod);

    for (size_t k = 0; k < count; ++k) {
      uint64_t correction_value = correction_lane[k];
      if (correction_value > correction_modulus_div_2) {
        output_q_coeffs[k] =
            qi.MulAddOptimized(correction_modulus - correction_value,
                               prod_operand, output_q_coeffs[k]);
      } else {
        output_q_coeffs[k] = qi.MulAddOptimized(
            correction_value, neg_prod_operand, output_q_coeffs[k]);
      }
    }
  }
  if (profile) {
    step8_shenoy_kumaresan_us =
        micros_between(step8_shenoy_kumaresan_begin, Clock::now());
    const auto total_us = micros_between(total_begin_time, Clock::now());
    std::cerr << "[HEU_SCALE_PROFILE] count=" << count
              << " step6_mul_us=" << step6_multiply_us
              << " step7_conv_us=" << step7_convert_us
              << " step7_fix_us=" << step7_adjust_us
              << " step8_conv_us=" << step8_convert_us
              << " step8_correction_us=" << step8_correction_lane_us
              << " step8_sk_us=" << step8_shenoy_kumaresan_us
              << " total_us=" << total_us << '\n';
  }
}

void ResidueTransferEngine::scale(const std::vector<uint64_t> &rests,
                                  std::vector<uint64_t> &out,
                                  size_t starting_index,
                                  ArenaHandle pool) const {
  const auto &aux_base = impl_->aux_base_scale;
  assert(rests.size() == impl_->from->moduli_u64().size());
  assert(!out.empty());
  assert(starting_index + out.size() <= impl_->to->moduli_u64().size());

  if (impl_->active_scaling_scheme == RnsScalingScheme::AuxBase) {
    if (!aux_base.ready) {
      throw std::runtime_error(
          "ResidueTransferEngine: auxiliary-base backend parameters are not "
          "initialized");
    }
    if (starting_index != 0 || out.size() != aux_base.base_q_size) {
      throw std::invalid_argument(
          "ResidueTransferEngine: auxiliary-base backend requires full base-q "
          "output");
    }
    std::vector<const uint64_t *> in_ptrs(rests.size());
    std::vector<uint64_t *> out_ptrs(out.size());
    for (size_t i = 0; i < rests.size(); ++i) {
      in_ptrs[i] = &rests[i];
    }
    for (size_t i = 0; i < out.size(); ++i) {
      out_ptrs[i] = &out[i];
    }
    impl_->scale_batch_aux_base(in_ptrs, out_ptrs, 1, pool);
    return;
  }
  impl_->residue_transfer_backend->scale(rests, out, starting_index, pool);
}

void ResidueTransferEngine::scale(const uint64_t *rests, uint64_t *out,
                                  size_t starting_index,
                                  ArenaHandle pool) const {
  if (!rests || !out) {
    throw std::invalid_argument(
        "ResidueTransferEngine::scale: null input/output pointer");
  }
  const size_t from_size = impl_->from->moduli_u64().size();
  const size_t to_size = impl_->to->moduli_u64().size() - starting_index;

  std::vector<const uint64_t *> in_ptrs(from_size);
  std::vector<uint64_t *> out_ptrs(to_size);
  for (size_t i = 0; i < from_size; ++i) {
    in_ptrs[i] = rests + i;
  }
  for (size_t i = 0; i < to_size; ++i) {
    out_ptrs[i] = out + i;
  }
  scale_batch(in_ptrs, out_ptrs, 1, starting_index, pool);
}

ResidueTransferEngine::ResidueTransferEngine(
    const std::shared_ptr<RnsContext> &from,
    const std::shared_ptr<RnsContext> &to, const ScalingFactor &scaling_factor)
    : impl_(std::make_unique<Impl>(from, to, scaling_factor)) {}

ResidueTransferEngine::~ResidueTransferEngine() = default;

std::shared_ptr<RnsContext> ResidueTransferEngine::from() const {
  return impl_->from;
}

std::shared_ptr<RnsContext> ResidueTransferEngine::to() const {
  return impl_->to;
}

bool ResidueTransferEngine::uses_aux_base_multiply_path() const {
  return impl_->active_scaling_scheme == RnsScalingScheme::AuxBase;
}

std::vector<uint64_t> ResidueTransferEngine::scale_new(
    const std::vector<uint64_t> &rests, size_t size) const {
  std::vector<uint64_t> out(size, 0);
  scale(rests, out, 0);
  return out;
}

void ResidueTransferEngine::scale_batch(
    const std::vector<const uint64_t *> &input_moduli_ptrs,
    const std::vector<uint64_t *> &output_moduli_ptrs, size_t count,
    size_t starting_index, ArenaHandle pool) const {
  const auto &aux_base = impl_->aux_base_scale;
  const size_t from_size = impl_->from->moduli_u64().size();
  const size_t to_size = output_moduli_ptrs.size();

  if (input_moduli_ptrs.size() != from_size) {
    throw std::invalid_argument("Input moduli ptrs count mismatch");
  }

  if (impl_->active_scaling_scheme == RnsScalingScheme::AuxBase) {
    if (!aux_base.ready) {
      throw std::runtime_error(
          "ResidueTransferEngine: auxiliary-base backend parameters are not "
          "initialized");
    }
    if (starting_index != 0) {
      throw std::invalid_argument(
          "ResidueTransferEngine: auxiliary-base backend requires "
          "starting_index == 0");
    }
    if (to_size != aux_base.base_q_size) {
      throw std::invalid_argument(
          "ResidueTransferEngine: auxiliary-base backend requires full base-q "
          "output");
    }
    impl_->scale_batch_aux_base(input_moduli_ptrs, output_moduli_ptrs, count,
                                pool);
    return;
  }
  impl_->residue_transfer_backend->scale_batch(
      input_moduli_ptrs, output_moduli_ptrs, count, starting_index, pool);
}

void ResidueTransferEngine::scale_poly(
    const std::vector<std::vector<uint64_t>> &coeffs_matrix,
    std::vector<std::vector<uint64_t>> &out_matrix, size_t starting_index,
    ArenaHandle pool) const {
  const size_t degree = coeffs_matrix.size();
  const size_t from_moduli_count = impl_->from->moduli_u64().size();
  const size_t to_moduli_count = impl_->to->moduli_u64().size();
  const size_t output_moduli_count = to_moduli_count - starting_index;

  if (degree == 0 || coeffs_matrix[0].size() != from_moduli_count) {
    throw std::invalid_argument("Invalid input coefficient matrix dimensions");
  }

  // Resize output matrix
  out_matrix.resize(degree);
  for (auto &row : out_matrix) {
    row.resize(output_moduli_count);
  }

  // Repack coefficient-major input into modulus-major scratch views.
  auto input_buf = pool.allocate<uint64_t>(from_moduli_count * degree);
  std::vector<const uint64_t *> input_ptrs(from_moduli_count);

  for (size_t k = 0; k < from_moduli_count; ++k) {
    uint64_t *col_ptr = input_buf.get() + k * degree;
    input_ptrs[k] = col_ptr;
    for (size_t c = 0; c < degree; ++c) {
      col_ptr[c] = coeffs_matrix[c][k];
    }
  }

  // Accumulate each output modulus in a dedicated scratch row.
  auto output_buf = pool.allocate<uint64_t>(output_moduli_count * degree);
  std::vector<uint64_t *> output_ptrs(output_moduli_count);

  for (size_t k = 0; k < output_moduli_count; ++k) {
    output_ptrs[k] = output_buf.get() + k * degree;
  }

  // Batch Call
  scale_batch(input_ptrs, output_ptrs, degree, starting_index, pool);

  // Copy back results
  for (size_t c = 0; c < degree; ++c) {
    for (size_t k = 0; k < output_moduli_count; ++k) {
      out_matrix[c][k] = output_ptrs[k][c];
    }
  }
}

void ResidueTransferEngine::scale_multi_poly(
    const std::vector<std::vector<std::vector<uint64_t>>> &polys_coeffs,
    std::vector<std::vector<std::vector<uint64_t>>> &out_polys_coeffs,
    size_t starting_index, ArenaHandle pool) const {
  const size_t num_polys = polys_coeffs.size();
  if (num_polys == 0) return;

  const size_t degree = polys_coeffs[0].size();
  const size_t from_moduli_count = impl_->from->moduli_u64().size();
  const size_t to_moduli_count = impl_->to->moduli_u64().size();
  const size_t output_moduli_count = to_moduli_count - starting_index;

  // Validate input dimensions
  for (const auto &poly_coeffs : polys_coeffs) {
    if (poly_coeffs.size() != degree) {
      throw std::invalid_argument("All polynomials must have the same degree");
    }
    if (degree > 0 && poly_coeffs[0].size() != from_moduli_count) {
      throw std::invalid_argument("Invalid coefficient matrix dimensions");
    }
  }

  // Resize output
  out_polys_coeffs.resize(num_polys);
  for (auto &poly_out : out_polys_coeffs) {
    poly_out.resize(degree);
    for (auto &coeff_row : poly_out) {
      coeff_row.resize(output_moduli_count);
    }
  }

  // OPTIMIZED: Process all polynomials together to improve cache locality
  // Pre-allocate temporary vectors to avoid repeated allocations
  std::vector<uint64_t> temp_input(from_moduli_count);
  std::vector<uint64_t> temp_output(output_moduli_count);

  // Process coefficient by coefficient across all polynomials
  for (size_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
    for (size_t poly_idx = 0; poly_idx < num_polys; ++poly_idx) {
      // Copy input coefficient
      const auto &input_coeff = polys_coeffs[poly_idx][coeff_idx];
      std::copy(input_coeff.begin(), input_coeff.end(), temp_input.begin());

      // Scale this coefficient
      scale(temp_input, temp_output, starting_index);

      // Copy result
      std::copy(temp_output.begin(), temp_output.end(),
                out_polys_coeffs[poly_idx][coeff_idx].begin());
    }
  }
}

}  // namespace rns
}  // namespace math
}  // namespace bfv
