#include "math/ntt.h"

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>  // Added for AVX512 intrinsics
#endif

#include <bitset>
#include <cassert>
#include <memory>
#include <random>
#include <vector>

#include "math/arch.h"
#include "math/ntt_harvey.h"
#include "math/ntt_optimized.h"
#include "math/ntt_tables.h"
// #include "util/profiling.h"
// #include "util/profiling.h"

// Optional strict bound checking for lazy ranges
#ifndef PULSAR_ASSERT_IN_RANGE
#ifdef PULSAR_NTT_STRICT_BOUNDS
#define PULSAR_ASSERT_IN_RANGE(x, bound) assert((x) < (bound))
#else
#define PULSAR_ASSERT_IN_RANGE(x, bound) ((void)0)
#endif
#endif

#ifdef PULSAR_NTT_OMP
#ifndef PULSAR_NTT_OMP_MIN_M
#define PULSAR_NTT_OMP_MIN_M 256
#endif
#ifndef PULSAR_NTT_OMP_MIN_L
#define PULSAR_NTT_OMP_MIN_L 32
#endif
#endif

namespace bfv {
namespace math {
namespace ntt {

// Branchless fold prototype (used by Backward/Forward before its definition)
static inline uint64_t Fold2P(uint64_t x, uint64_t twice_p);

// Hot helpers forward declarations
static inline __attribute__((always_inline)) uint64_t
LazyMulShoupLocal(uint64_t a, uint64_t b, uint64_t b_shoup, uint64_t p);
static inline __attribute__((always_inline)) uint64_t MulShoupAReducedLocal(
    uint64_t a_in_0_2p, uint64_t b, uint64_t b_shoup, uint64_t p);

// Added AVX512 vectorized helpers
#ifdef __AVX512F__
static inline __m512i Fold2PV(__m512i x, uint64_t twice_p) {
  __m512i twice_p_v = _mm512_set1_epi64(twice_p);
  __mmask8 ge = _mm512_cmp_epu64_mask(x, twice_p_v, _MM_CMPINT_GE);
  return _mm512_mask_sub_epi64(x, ge, x, twice_p_v);
}

static inline __m512i FoldPV(__m512i x, uint64_t p) {
  __m512i p_v = _mm512_set1_epi64(p);
  __mmask8 ge = _mm512_cmp_epu64_mask(x, p_v, _MM_CMPINT_GE);
  return _mm512_mask_sub_epi64(x, ge, x, p_v);
}

static inline __m512i Reduce3V(__m512i x, uint64_t p, uint64_t twice_p) {
  x = Fold2PV(x, twice_p);
  x = FoldPV(x, p);
  return x;
}

static inline __m512i MulHighV(__m512i x, __m512i y) {
  __m512i mask_low = _mm512_set1_epi64(0xFFFFFFFFULL);
  __m512i x0 = _mm512_and_si512(x, mask_low);
  __m512i x1 = _mm512_srli_epi64(x, 32);
  __m512i y0 = _mm512_and_si512(y, mask_low);
  __m512i y1 = _mm512_srli_epi64(y, 32);
  __m512i p00 = _mm512_mullo_epi64(x0, y0);
  __m512i p01 = _mm512_mullo_epi64(x0, y1);
  __m512i p10 = _mm512_mullo_epi64(x1, y0);
  __m512i p11 = _mm512_mullo_epi64(x1, y1);
  __m512i mid = _mm512_add_epi64(p01, p10);
  __m512i mid_high = _mm512_srli_epi64(mid, 32);
  __m512i high = _mm512_add_epi64(p11, mid_high);
  __m512i mid_low = _mm512_slli_epi64(mid, 32);
  __m512i low = _mm512_add_epi64(p00, mid_low);
  __mmask8 overflow = _mm512_cmp_epi64_mask(low, p00, _MM_CMPINT_LT);
  __m512i carry = _mm512_mask_blend_epi64(overflow, _mm512_setzero_si512(),
                                          _mm512_set1_epi64(1LL));
  high = _mm512_add_epi64(high, carry);
  return high;
}

static inline __m512i LazyMulShoupV(__m512i a, uint64_t b, uint64_t b_shoup,
                                    uint64_t p) {
  __m512i b_v = _mm512_set1_epi64(b);
  __m512i b_shoup_v = _mm512_set1_epi64(b_shoup);
  __m512i p_v = _mm512_set1_epi64(p);
  __m512i q = MulHighV(a, b_shoup_v);
  __m512i low = _mm512_mullo_epi64(a, b_v);
  __m512i qp = _mm512_mullo_epi64(q, p_v);
  __m512i r = _mm512_sub_epi64(low, qp);
  return r;
}

static inline __m512i MulShoupAReducedV(__m512i a_in_0_2p, uint64_t b,
                                        uint64_t b_shoup, uint64_t p) {
  __m512i a = FoldPV(a_in_0_2p, p);
  return LazyMulShoupV(a, b, b_shoup, p);
}
#endif

struct NttOperator::Impl {
  Impl(const zq::Modulus &mod, size_t s)
      : p(mod),
        p_twice(mod.P() * 2),
        size(s),
        omegas(),
        omegas_shoup(),
        zetas_inv(),
        zetas_inv_shoup(),
        size_inv(0),
        size_inv_shoup(0),
        ntt_tables_() {}

  zq::Modulus p;
  uint64_t p_twice;
  size_t size;
  std::vector<uint64_t> omegas;
  std::vector<uint64_t> omegas_shoup;
  std::vector<uint64_t> zetas_inv;
  std::vector<uint64_t> zetas_inv_shoup;
  uint64_t size_inv;
  uint64_t size_inv_shoup;
  std::optional<NTTTables> ntt_tables_;
};

NttOperator::NttOperator(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

NttOperator::NttOperator(const NttOperator &other)
    : impl_(std::make_unique<Impl>(*other.impl_)) {}

NttOperator::NttOperator(NttOperator &&other) noexcept
    : impl_(std::move(other.impl_)) {}

NttOperator::~NttOperator() = default;

bool SupportsNtt(uint64_t p, size_t size) {
  if (size < 8 || (size & (size - 1)) != 0) return false;
  if (p % 2 == 0 || p < 2) return false;
  return (p - 1) % (2 * size) == 0;
}

std::optional<NttOperator> NttOperator::New(const zq::Modulus &p, size_t size) {
  if (!SupportsNtt(p.P(), size)) {
    return std::nullopt;
  }
  auto size_inv_opt = p.Inv(size);
  if (!size_inv_opt) {
    return std::nullopt;
  }
  uint64_t size_inv = size_inv_opt.value();

  uint64_t omega = PrimitiveRoot(size, p);
  auto omega_inv_opt = p.Inv(omega);
  if (!omega_inv_opt) {
    return std::nullopt;
  }
  uint64_t omega_inv = omega_inv_opt.value();

  std::vector<uint64_t> powers(size);
  powers[0] = 1;
  for (size_t i = 1; i < size; ++i) {
    powers[i] = p.Mul(powers[i - 1], omega);
  }

  std::vector<uint64_t> powers_inv(size);
  powers_inv[0] = omega_inv;
  for (size_t i = 1; i < size; ++i) {
    powers_inv[i] = p.Mul(powers_inv[i - 1], omega_inv);
  }

  // Platform-specific bit reversal function
#if defined(__GNUC__) &&                                        \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)) && \
    defined(__has_builtin)
#if __has_builtin(__builtin_bitreverse64)
#define HAS_BUILTIN_BITREVERSE64 1
#endif
#endif

#ifndef HAS_BUILTIN_BITREVERSE64
  // Fallback bit reversal implementation for compilers without
  // __builtin_bitreverse64
  auto bit_reverse_64 = [](uint64_t x) -> uint64_t {
    x = ((x & 0x5555555555555555ULL) << 1) | ((x & 0xAAAAAAAAAAAAAAAAULL) >> 1);
    x = ((x & 0x3333333333333333ULL) << 2) | ((x & 0xCCCCCCCCCCCCCCCCULL) >> 2);
    x = ((x & 0x0F0F0F0F0F0F0F0FULL) << 4) | ((x & 0xF0F0F0F0F0F0F0F0ULL) >> 4);
    x = ((x & 0x00FF00FF00FF00FFULL) << 8) | ((x & 0xFF00FF00FF00FF00ULL) >> 8);
    x = ((x & 0x0000FFFF0000FFFFULL) << 16) |
        ((x & 0xFFFF0000FFFF0000ULL) >> 16);
    x = ((x & 0x00000000FFFFFFFFULL) << 32) |
        ((x & 0xFFFFFFFF00000000ULL) >> 32);
    return x;
  };
#endif

  std::vector<uint64_t> omegas(size);
  std::vector<uint64_t> zetas_inv(size);
  // Precompute leading zeros once (was redundantly computed in the loop)
  const size_t leading_zeros = __builtin_clzll(size) + 1;
  for (size_t i = 0; i < size; ++i) {
#ifdef HAS_BUILTIN_BITREVERSE64
    size_t j = __builtin_bitreverse64(i) >> leading_zeros;
#else
    size_t j = bit_reverse_64(i) >> leading_zeros;
#endif
    omegas[i] = powers[j];
    zetas_inv[i] = powers_inv[j];
  }

  auto omegas_shoup = p.ShoupVec(omegas);
  auto zetas_inv_shoup = p.ShoupVec(zetas_inv);

  auto impl = std::make_unique<Impl>(p, size);
  impl->omegas = std::move(omegas);
  impl->omegas_shoup = std::move(omegas_shoup);
  impl->zetas_inv = std::move(zetas_inv);
  impl->zetas_inv_shoup = std::move(zetas_inv_shoup);
  impl->size_inv = size_inv;
  impl->size_inv_shoup = p.Shoup(size_inv);

  // Initialize Harvey NTT tables
  auto tables_opt = NTTTables::Create(p, size);
  if (tables_opt.has_value()) {
    impl->ntt_tables_.emplace(std::move(*tables_opt));
  }

  return NttOperator(std::move(impl));
}

void NttOperator::ForwardCore(uint64_t *data, bool reduce_output) const {
  uint64_t *__restrict a_ptr = data;
#ifdef __AVX512F__
  const uint64_t pmod = impl_->p.P();
#endif
  size_t l = impl_->size >> 1;
  size_t m = 1;
  size_t k = 1;
  while (l > 0) {
    const bool final_stage = (l == 1);
#ifdef PULSAR_NTT_PF_OVERRIDE
    const size_t pf_val = static_cast<size_t>(PULSAR_NTT_PF_OVERRIDE);
#else
    const size_t pf_val = 16;
#endif
    // Optimized prefetch strategy: enable for larger blocks to improve cache
    // efficiency
    const size_t pf_elems = (l >= 32 && l <= 1024) ? pf_val : 0;
    size_t base_k = k;
    const uint64_t *__restrict w_ptr = impl_->omegas.data() + base_k;
    const uint64_t *__restrict wsh_ptr = impl_->omegas_shoup.data() + base_k;
#ifdef PULSAR_NTT_OMP
#pragma omp parallel for if (m >= PULSAR_NTT_OMP_MIN_M && \
                                 l >= PULSAR_NTT_OMP_MIN_L) schedule(static)
#endif
    for (size_t i = 0; i < m; ++i) {
      uint64_t omega = w_ptr[i];
      uint64_t omega_shoup = wsh_ptr[i];
      size_t s = 2 * i * l;
      // Use pointer slices to reduce address arithmetic and aid vectorizer
      uint64_t *__restrict u_ptr = a_ptr + s;
      uint64_t *__restrict v_ptr = u_ptr + l;
      size_t kk = 0;
      if (!final_stage || !reduce_output) {
#ifdef __AVX512F__
        // Improved vectorized loop with better alignment handling
        for (; kk + 8 <= l; kk += 8) {
          if (pf_elems && kk + pf_elems < l) {
            __builtin_prefetch(u_ptr + kk + pf_elems, 1, 2);
            __builtin_prefetch(v_ptr + kk + pf_elems, 1, 2);
          }
          __m512i u = _mm512_loadu_si512(u_ptr + kk);
          __m512i v = _mm512_loadu_si512(v_ptr + kk);
          u = Fold2PV(u, impl_->p_twice);
          v = Fold2PV(v, impl_->p_twice);
          __m512i t = LazyMulShoupV(v, omega, omega_shoup, pmod);
          __m512i p_twice_v = _mm512_set1_epi64(impl_->p_twice);
          __m512i v_new = _mm512_add_epi64(u, p_twice_v);
          v_new = _mm512_sub_epi64(v_new, t);
          v = Fold2PV(v_new, impl_->p_twice);
          __m512i u_new = _mm512_add_epi64(u, t);
          u = Fold2PV(u_new, impl_->p_twice);
          _mm512_storeu_si512(u_ptr + kk, u);
          _mm512_storeu_si512(v_ptr + kk, v);
        }
#else
#pragma GCC ivdep
#pragma GCC unroll 8
        // Optimized scalar loop with improved prefetch timing
        for (; kk + 8 <= l; kk += 8) {
          if (pf_elems && kk + pf_elems < l) {
            __builtin_prefetch(u_ptr + kk + pf_elems, 1, 2);
            __builtin_prefetch(v_ptr + kk + pf_elems, 1, 2);
          }
          uint64_t &u0 = u_ptr[kk + 0], &v0 = v_ptr[kk + 0];
          Butterfly(u0, v0, omega, omega_shoup);
          uint64_t &u1 = u_ptr[kk + 1], &v1 = v_ptr[kk + 1];
          Butterfly(u1, v1, omega, omega_shoup);
          uint64_t &u2 = u_ptr[kk + 2], &v2 = v_ptr[kk + 2];
          Butterfly(u2, v2, omega, omega_shoup);
          uint64_t &u3 = u_ptr[kk + 3], &v3 = v_ptr[kk + 3];
          Butterfly(u3, v3, omega, omega_shoup);
          uint64_t &u4 = u_ptr[kk + 4], &v4 = v_ptr[kk + 4];
          Butterfly(u4, v4, omega, omega_shoup);
          uint64_t &u5 = u_ptr[kk + 5], &v5 = v_ptr[kk + 5];
          Butterfly(u5, v5, omega, omega_shoup);
          uint64_t &u6 = u_ptr[kk + 6], &v6 = v_ptr[kk + 6];
          Butterfly(u6, v6, omega, omega_shoup);
          uint64_t &u7 = u_ptr[kk + 7], &v7 = v_ptr[kk + 7];
          Butterfly(u7, v7, omega, omega_shoup);
        }
#endif
#pragma GCC ivdep
        for (; kk < l; ++kk) {
          if (pf_elems && kk + pf_elems < l) {
            __builtin_prefetch(u_ptr + kk + pf_elems, 1, 2);
            __builtin_prefetch(v_ptr + kk + pf_elems, 1, 2);
          }
          uint64_t &u = u_ptr[kk];
          uint64_t &v = v_ptr[kk];
          Butterfly(u, v, omega, omega_shoup);
          if (final_stage && reduce_output) {
            u = Reduce3(u);
            v = Reduce3(v);
          }
        }
      } else {
#ifdef __AVX512F__
        // Final stage with reduce3 - optimized prefetch
        for (; kk + 8 <= l; kk += 8) {
          if (pf_elems && kk + pf_elems < l) {
            __builtin_prefetch(u_ptr + kk + pf_elems, 1, 2);
            __builtin_prefetch(v_ptr + kk + pf_elems, 1, 2);
          }
          __m512i u = _mm512_loadu_si512(u_ptr + kk);
          __m512i v = _mm512_loadu_si512(v_ptr + kk);
          u = Fold2PV(u, impl_->p_twice);
          v = Fold2PV(v, impl_->p_twice);
          __m512i t = LazyMulShoupV(v, omega, omega_shoup, pmod);
          __m512i p_twice_v = _mm512_set1_epi64(impl_->p_twice);
          __m512i v_new = _mm512_add_epi64(u, p_twice_v);
          v_new = _mm512_sub_epi64(v_new, t);
          v = Fold2PV(v_new, impl_->p_twice);
          __m512i u_new = _mm512_add_epi64(u, t);
          u = Fold2PV(u_new, impl_->p_twice);
          u = Reduce3V(u, pmod, impl_->p_twice);
          v = Reduce3V(v, pmod, impl_->p_twice);
          _mm512_storeu_si512(u_ptr + kk, u);
          _mm512_storeu_si512(v_ptr + kk, v);
        }
#else
#pragma GCC ivdep
#pragma GCC unroll 8
        // Final stage scalar - minimal prefetch for better performance
        for (; kk + 8 <= l; kk += 8) {
          uint64_t &u0 = u_ptr[kk + 0], &v0 = v_ptr[kk + 0];
          Butterfly(u0, v0, omega, omega_shoup);
          u0 = Reduce3(u0);
          v0 = Reduce3(v0);
          uint64_t &u1 = u_ptr[kk + 1], &v1 = v_ptr[kk + 1];
          Butterfly(u1, v1, omega, omega_shoup);
          u1 = Reduce3(u1);
          v1 = Reduce3(v1);
          uint64_t &u2 = u_ptr[kk + 2], &v2 = v_ptr[kk + 2];
          Butterfly(u2, v2, omega, omega_shoup);
          u2 = Reduce3(u2);
          v2 = Reduce3(v2);
          uint64_t &u3 = u_ptr[kk + 3], &v3 = v_ptr[kk + 3];
          Butterfly(u3, v3, omega, omega_shoup);
          u3 = Reduce3(u3);
          v3 = Reduce3(v3);
          uint64_t &u4 = u_ptr[kk + 4], &v4 = v_ptr[kk + 4];
          Butterfly(u4, v4, omega, omega_shoup);
          u4 = Reduce3(u4);
          v4 = Reduce3(v4);
          uint64_t &u5 = u_ptr[kk + 5], &v5 = v_ptr[kk + 5];
          Butterfly(u5, v5, omega, omega_shoup);
          u5 = Reduce3(u5);
          v5 = Reduce3(v5);
          uint64_t &u6 = u_ptr[kk + 6], &v6 = v_ptr[kk + 6];
          Butterfly(u6, v6, omega, omega_shoup);
          u6 = Reduce3(u6);
          v6 = Reduce3(v6);
          uint64_t &u7 = u_ptr[kk + 7], &v7 = v_ptr[kk + 7];
          Butterfly(u7, v7, omega, omega_shoup);
          u7 = Reduce3(u7);
          v7 = Reduce3(v7);
        }
#endif
#pragma GCC ivdep
        for (; kk < l; ++kk) {
          uint64_t &u = u_ptr[kk];
          uint64_t &v = v_ptr[kk];
          Butterfly(u, v, omega, omega_shoup);
          u = Reduce3(u);
          v = Reduce3(v);
        }
      }
    }
    k += m;
    l >>= 1;
    m <<= 1;
  }
  // Final normalization fused into the last stage; no extra full pass needed
}

void NttOperator::BackwardCore(uint64_t *data, bool reduce_output) const {
  uint64_t *__restrict a_ptr = data;
  const uint64_t pmod = impl_->p.P();
  const uint64_t size_inv = impl_->size_inv;
  const uint64_t size_inv_shoup = impl_->size_inv_shoup;
  size_t m = impl_->size >> 1;
  size_t l = 1;
  size_t k = 0;
  while (m > 0) {
    const bool final_stage = (m == 1);
#ifdef PULSAR_NTT_PF_OVERRIDE
    const size_t pf_val = static_cast<size_t>(PULSAR_NTT_PF_OVERRIDE);
#else
    const size_t pf_val = 16;
#endif
    const size_t pf_elems = (l >= 64 && l <= 256) ? pf_val : 0;
    size_t base_k = k;
    const uint64_t *__restrict z_ptr = impl_->zetas_inv.data() + base_k;
    const uint64_t *__restrict zsh_ptr = impl_->zetas_inv_shoup.data() + base_k;
#ifdef PULSAR_NTT_OMP
#pragma omp parallel for if (m >= PULSAR_NTT_OMP_MIN_M && \
                                 l >= PULSAR_NTT_OMP_MIN_L) schedule(static)
#endif
    for (size_t i = 0; i < m; ++i) {
      size_t s = 2 * i * l;
      uint64_t zeta_inv = z_ptr[i];
      uint64_t zeta_inv_shoup = zsh_ptr[i];
      uint64_t *__restrict u_ptr = a_ptr + s;
      uint64_t *__restrict v_ptr = u_ptr + l;
      size_t kk = 0;
      if (!final_stage) {
#ifdef __AVX512F__
        for (; kk + 8 <= l; kk += 8) {
          if (pf_elems) {
            size_t pu = kk + pf_elems;
            if (pu < l) __builtin_prefetch(u_ptr + pu, 1, 1);
            size_t pv = kk + pf_elems;
            if (pv < l) __builtin_prefetch(v_ptr + pv, 1, 1);
          }
          __m512i u = _mm512_loadu_si512(u_ptr + kk);
          __m512i v = _mm512_loadu_si512(v_ptr + kk);
          __m512i p_twice_v = _mm512_set1_epi64(impl_->p_twice);
          __m512i u_add = _mm512_add_epi64(u, v);
          u_add = Fold2PV(u_add, impl_->p_twice);
          __m512i d = _mm512_add_epi64(u, p_twice_v);
          d = _mm512_sub_epi64(d, v);
          d = Fold2PV(d, impl_->p_twice);
          v = LazyMulShoupV(d, zeta_inv, zeta_inv_shoup, pmod);
          u = u_add;
          _mm512_storeu_si512(u_ptr + kk, u);
          _mm512_storeu_si512(v_ptr + kk, v);
        }
#else
#pragma GCC ivdep
#pragma GCC unroll 8
        for (; kk + 8 <= l; kk += 8) {
          if (pf_elems) {
            size_t pu = kk + pf_elems;
            if (pu < l) __builtin_prefetch(u_ptr + pu, 1, 1);
            size_t pv = kk + pf_elems;
            if (pv < l) __builtin_prefetch(v_ptr + pv, 1, 1);
          }
          uint64_t &u0 = u_ptr[kk + 0], &v0 = v_ptr[kk + 0];
          uint64_t u0_add = Fold2P(u0 + v0, impl_->p_twice);
          uint64_t d0 = Fold2P(u0 + impl_->p_twice - v0, impl_->p_twice);
          v0 = LazyMulShoupLocal(d0, zeta_inv, zeta_inv_shoup, pmod);
          u0 = u0_add;

          uint64_t &u1 = u_ptr[kk + 1], &v1 = v_ptr[kk + 1];
          uint64_t u1_add = Fold2P(u1 + v1, impl_->p_twice);
          uint64_t d1 = Fold2P(u1 + impl_->p_twice - v1, impl_->p_twice);
          v1 = LazyMulShoupLocal(d1, zeta_inv, zeta_inv_shoup, pmod);
          u1 = u1_add;

          uint64_t &u2 = u_ptr[kk + 2], &v2 = v_ptr[kk + 2];
          uint64_t u2_add = Fold2P(u2 + v2, impl_->p_twice);
          uint64_t d2 = Fold2P(u2 + impl_->p_twice - v2, impl_->p_twice);
          v2 = LazyMulShoupLocal(d2, zeta_inv, zeta_inv_shoup, pmod);
          u2 = u2_add;

          uint64_t &u3 = u_ptr[kk + 3], &v3 = v_ptr[kk + 3];
          uint64_t u3_add = Fold2P(u3 + v3, impl_->p_twice);
          uint64_t d3 = Fold2P(u3 + impl_->p_twice - v3, impl_->p_twice);
          v3 = LazyMulShoupLocal(d3, zeta_inv, zeta_inv_shoup, pmod);
          u3 = u3_add;

          uint64_t &u4 = u_ptr[kk + 4], &v4 = v_ptr[kk + 4];
          uint64_t u4_add = Fold2P(u4 + v4, impl_->p_twice);
          uint64_t d4 = Fold2P(u4 + impl_->p_twice - v4, impl_->p_twice);
          v4 = LazyMulShoupLocal(d4, zeta_inv, zeta_inv_shoup, pmod);
          u4 = u4_add;

          uint64_t &u5 = u_ptr[kk + 5], &v5 = v_ptr[kk + 5];
          uint64_t u5_add = Fold2P(u5 + v5, impl_->p_twice);
          uint64_t d5 = Fold2P(u5 + impl_->p_twice - v5, impl_->p_twice);
          v5 = LazyMulShoupLocal(d5, zeta_inv, zeta_inv_shoup, pmod);
          u5 = u5_add;

          uint64_t &u6 = u_ptr[kk + 6], &v6 = v_ptr[kk + 6];
          uint64_t u6_add = Fold2P(u6 + v6, impl_->p_twice);
          uint64_t d6 = Fold2P(u6 + impl_->p_twice - v6, impl_->p_twice);
          v6 = LazyMulShoupLocal(d6, zeta_inv, zeta_inv_shoup, pmod);
          u6 = u6_add;

          uint64_t &u7 = u_ptr[kk + 7], &v7 = v_ptr[kk + 7];
          uint64_t u7_add = Fold2P(u7 + v7, impl_->p_twice);
          uint64_t d7 = Fold2P(u7 + impl_->p_twice - v7, impl_->p_twice);
          v7 = LazyMulShoupLocal(d7, zeta_inv, zeta_inv_shoup, pmod);
          u7 = u7_add;
        }
#endif
#pragma GCC ivdep
        for (; kk < l; ++kk) {
          if (pf_elems) {
            size_t pu = kk + pf_elems;
            if (pu < l) __builtin_prefetch(u_ptr + pu, 1, 1);
            size_t pv = kk + pf_elems;
            if (pv < l) __builtin_prefetch(v_ptr + pv, 1, 1);
          }
          uint64_t &u = u_ptr[kk];
          uint64_t &v = v_ptr[kk];
          uint64_t u_add = Fold2P(u + v, impl_->p_twice);
          uint64_t d = Fold2P(u + impl_->p_twice - v, impl_->p_twice);
          v = LazyMulShoupLocal(d, zeta_inv, zeta_inv_shoup, pmod);
          u = u_add;
        }
      } else {
#ifdef __AVX512F__
        for (; kk + 8 <= l; kk += 8) {
          if (pf_elems) {
            size_t pu = kk + pf_elems;
            if (pu < l) __builtin_prefetch(u_ptr + pu, 1, 1);
            size_t pv = kk + pf_elems;
            if (pv < l) __builtin_prefetch(v_ptr + pv, 1, 1);
          }
          __m512i u = _mm512_loadu_si512(u_ptr + kk);
          __m512i v = _mm512_loadu_si512(v_ptr + kk);
          __m512i p_twice_v = _mm512_set1_epi64(impl_->p_twice);
          __m512i u_add = _mm512_add_epi64(u, v);
          u_add = Fold2PV(u_add, impl_->p_twice);
          __m512i d = _mm512_add_epi64(u, p_twice_v);
          d = _mm512_sub_epi64(d, v);
          d = Fold2PV(d, impl_->p_twice);
          __m512i d_mul = LazyMulShoupV(d, zeta_inv, zeta_inv_shoup, pmod);
          if (reduce_output) {
            v = MulShoupAReducedV(d_mul, size_inv, size_inv_shoup, pmod);
            u = MulShoupAReducedV(u_add, size_inv, size_inv_shoup, pmod);
          } else {
            v = LazyMulShoupV(FoldPV(d_mul, pmod), size_inv, size_inv_shoup,
                              pmod);
            u = LazyMulShoupV(FoldPV(u_add, pmod), size_inv, size_inv_shoup,
                              pmod);
          }
          _mm512_storeu_si512(u_ptr + kk, u);
          _mm512_storeu_si512(v_ptr + kk, v);
        }
#else
#pragma GCC ivdep
#pragma GCC unroll 8
        for (; kk + 8 <= l; kk += 8) {
          uint64_t &u0 = u_ptr[kk + 0], &v0 = v_ptr[kk + 0];
          uint64_t u0_add = Fold2P(u0 + v0, impl_->p_twice);
          uint64_t d0 = Fold2P(u0 + impl_->p_twice - v0, impl_->p_twice);
          if (reduce_output) {
            v0 = MulShoupAReducedLocal(
                LazyMulShoupLocal(d0, zeta_inv, zeta_inv_shoup, pmod), size_inv,
                size_inv_shoup, pmod);
            u0 = MulShoupAReducedLocal(u0_add, size_inv, size_inv_shoup, pmod);
          } else {
            uint64_t d0_mul =
                LazyMulShoupLocal(d0, zeta_inv, zeta_inv_shoup, pmod);
            d0_mul -= pmod & (0 - static_cast<uint64_t>(d0_mul >= pmod));
            uint64_t u0_red =
                u0_add - (pmod & (0 - static_cast<uint64_t>(u0_add >= pmod)));
            v0 = LazyMulShoupLocal(d0_mul, size_inv, size_inv_shoup, pmod);
            u0 = LazyMulShoupLocal(u0_red, size_inv, size_inv_shoup, pmod);
          }

          uint64_t &u1 = u_ptr[kk + 1], &v1 = v_ptr[kk + 1];
          uint64_t u1_add = Fold2P(u1 + v1, impl_->p_twice);
          uint64_t d1 = Fold2P(u1 + impl_->p_twice - v1, impl_->p_twice);
          if (reduce_output) {
            v1 = MulShoupAReducedLocal(
                LazyMulShoupLocal(d1, zeta_inv, zeta_inv_shoup, pmod), size_inv,
                size_inv_shoup, pmod);
            u1 = MulShoupAReducedLocal(u1_add, size_inv, size_inv_shoup, pmod);
          } else {
            uint64_t d1_mul =
                LazyMulShoupLocal(d1, zeta_inv, zeta_inv_shoup, pmod);
            d1_mul -= pmod & (0 - static_cast<uint64_t>(d1_mul >= pmod));
            uint64_t u1_red =
                u1_add - (pmod & (0 - static_cast<uint64_t>(u1_add >= pmod)));
            v1 = LazyMulShoupLocal(d1_mul, size_inv, size_inv_shoup, pmod);
            u1 = LazyMulShoupLocal(u1_red, size_inv, size_inv_shoup, pmod);
          }

          uint64_t &u2 = u_ptr[kk + 2], &v2 = v_ptr[kk + 2];
          uint64_t u2_add = Fold2P(u2 + v2, impl_->p_twice);
          uint64_t d2 = Fold2P(u2 + impl_->p_twice - v2, impl_->p_twice);
          if (reduce_output) {
            v2 = MulShoupAReducedLocal(
                LazyMulShoupLocal(d2, zeta_inv, zeta_inv_shoup, pmod), size_inv,
                size_inv_shoup, pmod);
            u2 = MulShoupAReducedLocal(u2_add, size_inv, size_inv_shoup, pmod);
          } else {
            uint64_t d2_mul =
                LazyMulShoupLocal(d2, zeta_inv, zeta_inv_shoup, pmod);
            d2_mul -= pmod & (0 - static_cast<uint64_t>(d2_mul >= pmod));
            uint64_t u2_red =
                u2_add - (pmod & (0 - static_cast<uint64_t>(u2_add >= pmod)));
            v2 = LazyMulShoupLocal(d2_mul, size_inv, size_inv_shoup, pmod);
            u2 = LazyMulShoupLocal(u2_red, size_inv, size_inv_shoup, pmod);
          }

          uint64_t &u3 = u_ptr[kk + 3], &v3 = v_ptr[kk + 3];
          uint64_t u3_add = Fold2P(u3 + v3, impl_->p_twice);
          uint64_t d3 = Fold2P(u3 + impl_->p_twice - v3, impl_->p_twice);
          if (reduce_output) {
            v3 = MulShoupAReducedLocal(
                LazyMulShoupLocal(d3, zeta_inv, zeta_inv_shoup, pmod), size_inv,
                size_inv_shoup, pmod);
            u3 = MulShoupAReducedLocal(u3_add, size_inv, size_inv_shoup, pmod);
          } else {
            uint64_t d3_mul =
                LazyMulShoupLocal(d3, zeta_inv, zeta_inv_shoup, pmod);
            d3_mul -= pmod & (0 - static_cast<uint64_t>(d3_mul >= pmod));
            uint64_t u3_red =
                u3_add - (pmod & (0 - static_cast<uint64_t>(u3_add >= pmod)));
            v3 = LazyMulShoupLocal(d3_mul, size_inv, size_inv_shoup, pmod);
            u3 = LazyMulShoupLocal(u3_red, size_inv, size_inv_shoup, pmod);
          }

          uint64_t &u4 = u_ptr[kk + 4], &v4 = v_ptr[kk + 4];
          uint64_t u4_add = Fold2P(u4 + v4, impl_->p_twice);
          uint64_t d4 = Fold2P(u4 + impl_->p_twice - v4, impl_->p_twice);
          if (reduce_output) {
            v4 = MulShoupAReducedLocal(
                LazyMulShoupLocal(d4, zeta_inv, zeta_inv_shoup, pmod), size_inv,
                size_inv_shoup, pmod);
            u4 = MulShoupAReducedLocal(u4_add, size_inv, size_inv_shoup, pmod);
          } else {
            uint64_t d4_mul =
                LazyMulShoupLocal(d4, zeta_inv, zeta_inv_shoup, pmod);
            d4_mul -= pmod & (0 - static_cast<uint64_t>(d4_mul >= pmod));
            uint64_t u4_red =
                u4_add - (pmod & (0 - static_cast<uint64_t>(u4_add >= pmod)));
            v4 = LazyMulShoupLocal(d4_mul, size_inv, size_inv_shoup, pmod);
            u4 = LazyMulShoupLocal(u4_red, size_inv, size_inv_shoup, pmod);
          }

          uint64_t &u5 = u_ptr[kk + 5], &v5 = v_ptr[kk + 5];
          uint64_t u5_add = Fold2P(u5 + v5, impl_->p_twice);
          uint64_t d5 = Fold2P(u5 + impl_->p_twice - v5, impl_->p_twice);
          if (reduce_output) {
            v5 = MulShoupAReducedLocal(
                LazyMulShoupLocal(d5, zeta_inv, zeta_inv_shoup, pmod), size_inv,
                size_inv_shoup, pmod);
            u5 = MulShoupAReducedLocal(u5_add, size_inv, size_inv_shoup, pmod);
          } else {
            uint64_t d5_mul =
                LazyMulShoupLocal(d5, zeta_inv, zeta_inv_shoup, pmod);
            d5_mul -= pmod & (0 - static_cast<uint64_t>(d5_mul >= pmod));
            uint64_t u5_red =
                u5_add - (pmod & (0 - static_cast<uint64_t>(u5_add >= pmod)));
            v5 = LazyMulShoupLocal(d5_mul, size_inv, size_inv_shoup, pmod);
            u5 = LazyMulShoupLocal(u5_red, size_inv, size_inv_shoup, pmod);
          }

          uint64_t &u6 = u_ptr[kk + 6], &v6 = v_ptr[kk + 6];
          uint64_t u6_add = Fold2P(u6 + v6, impl_->p_twice);
          uint64_t d6 = Fold2P(u6 + impl_->p_twice - v6, impl_->p_twice);
          if (reduce_output) {
            v6 = MulShoupAReducedLocal(
                LazyMulShoupLocal(d6, zeta_inv, zeta_inv_shoup, pmod), size_inv,
                size_inv_shoup, pmod);
            u6 = MulShoupAReducedLocal(u6_add, size_inv, size_inv_shoup, pmod);
          } else {
            uint64_t d6_mul =
                LazyMulShoupLocal(d6, zeta_inv, zeta_inv_shoup, pmod);
            d6_mul -= pmod & (0 - static_cast<uint64_t>(d6_mul >= pmod));
            uint64_t u6_red =
                u6_add - (pmod & (0 - static_cast<uint64_t>(u6_add >= pmod)));
            v6 = LazyMulShoupLocal(d6_mul, size_inv, size_inv_shoup, pmod);
            u6 = LazyMulShoupLocal(u6_red, size_inv, size_inv_shoup, pmod);
          }

          uint64_t &u7 = u_ptr[kk + 7], &v7 = v_ptr[kk + 7];
          uint64_t u7_add = Fold2P(u7 + v7, impl_->p_twice);
          uint64_t d7 = Fold2P(u7 + impl_->p_twice - v7, impl_->p_twice);
          if (reduce_output) {
            v7 = MulShoupAReducedLocal(
                LazyMulShoupLocal(d7, zeta_inv, zeta_inv_shoup, pmod), size_inv,
                size_inv_shoup, pmod);
            u7 = MulShoupAReducedLocal(u7_add, size_inv, size_inv_shoup, pmod);
          } else {
            uint64_t d7_mul =
                LazyMulShoupLocal(d7, zeta_inv, zeta_inv_shoup, pmod);
            d7_mul -= pmod & (0 - static_cast<uint64_t>(d7_mul >= pmod));
            uint64_t u7_red =
                u7_add - (pmod & (0 - static_cast<uint64_t>(u7_add >= pmod)));
            v7 = LazyMulShoupLocal(d7_mul, size_inv, size_inv_shoup, pmod);
            u7 = LazyMulShoupLocal(u7_red, size_inv, size_inv_shoup, pmod);
          }
        }
#endif
#pragma GCC ivdep
        for (; kk < l; ++kk) {
          uint64_t &u = u_ptr[kk];
          uint64_t &v = v_ptr[kk];
          uint64_t u_add = Fold2P(u + v, impl_->p_twice);
          uint64_t d = Fold2P(u + impl_->p_twice - v, impl_->p_twice);
          if (reduce_output) {
            v = MulShoupAReducedLocal(
                LazyMulShoupLocal(d, zeta_inv, zeta_inv_shoup, pmod), size_inv,
                size_inv_shoup, pmod);
            u = MulShoupAReducedLocal(u_add, size_inv, size_inv_shoup, pmod);
          } else {
            uint64_t d_mul =
                LazyMulShoupLocal(d, zeta_inv, zeta_inv_shoup, pmod);
            d_mul -= pmod & (0 - static_cast<uint64_t>(d_mul >= pmod));
            uint64_t u_red =
                u_add - (pmod & (0 - static_cast<uint64_t>(u_add >= pmod)));
            v = LazyMulShoupLocal(d_mul, size_inv, size_inv_shoup, pmod);
            u = LazyMulShoupLocal(u_red, size_inv, size_inv_shoup, pmod);
          }
        }
      }
    }
    k += m;
    l <<= 1;
    m >>= 1;
  }
}

std::vector<uint64_t> NttOperator::Forward(
    const std::vector<uint64_t> &input) const {
  std::vector<uint64_t> a = input;
  assert(a.size() == impl_->size);
  ForwardInPlace(a.data());
  return a;
}

std::vector<uint64_t> NttOperator::ForwardVtLazy(
    const std::vector<uint64_t> &input) const {
  std::vector<uint64_t> a = input;
  assert(a.size() == impl_->size);
  ForwardInPlaceLazy(a.data());
  return a;
}

std::vector<uint64_t> NttOperator::ForwardVt(
    const std::vector<uint64_t> &input) const {
  auto a = ForwardVtLazy(input);
  for (auto &x : a) x = Reduce3(x);
  return a;
}

std::vector<uint64_t> NttOperator::Backward(
    const std::vector<uint64_t> &input) const {
  std::vector<uint64_t> a = input;
  assert(a.size() == impl_->size);
  BackwardInPlace(a.data());
  return a;
}

std::vector<uint64_t> NttOperator::BackwardVt(
    const std::vector<uint64_t> &input) const {
  std::vector<uint64_t> a = input;
  assert(a.size() == impl_->size);
  uint64_t *a_ptr = a.data();
  size_t k = 0;
  size_t m = impl_->size >> 1;
  size_t l = 1;
  while (m > 0) {
    for (size_t i = 0; i < m; ++i) {
      size_t s = 2 * i * l;
      uint64_t zeta_inv = impl_->zetas_inv[k];
      uint64_t zeta_inv_shoup = impl_->zetas_inv_shoup[k];
      k++;
      for (size_t j = s; j < s + l; ++j) {
        uint64_t &uj = *(a_ptr + j);
        uint64_t &ujl = *(a_ptr + j + l);
        InvButterflyVt(uj, ujl, zeta_inv, zeta_inv_shoup);
      }
    }
    l <<= 1;
    m >>= 1;
  }
  for (auto &x : a) {
    x = impl_->p.MulShoupVt(x, impl_->size_inv, impl_->size_inv_shoup);
  }
  return a;
}

std::vector<uint64_t> NttOperator::Reduce3Vt(
    const std::vector<uint64_t> &a) const {
  std::vector<uint64_t> res(a.size());
  for (size_t i = 0; i < a.size(); ++i) res[i] = Reduce3(a[i]);
  return res;
}

inline __attribute__((always_inline)) uint64_t
NttOperator::Reduce3(uint64_t x) const {
  assert(x < 4 * impl_->p.P());
  uint64_t y = (x >= impl_->p_twice) ? x - impl_->p_twice : x;
  return (y >= impl_->p.P()) ? y - impl_->p.P() : y;
}

// Add reduce3_vt

// Branchless fold from [0, 4p) to [0, 2p)
static inline uint64_t Fold2P(uint64_t x, uint64_t twice_p) {
  uint64_t ge = static_cast<uint64_t>(x >= twice_p);
  return x - (twice_p & (0 - ge));
}

// Hot inline helpers to avoid pimpl overhead in inner loops
static inline __attribute__((always_inline)) uint64_t
LazyMulShoupLocal(uint64_t a, uint64_t b, uint64_t b_shoup, uint64_t p) {
  __uint128_t q =
      (static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b_shoup)) >> 64;
  __uint128_t r =
      static_cast<__uint128_t>(a) * b - q * static_cast<__uint128_t>(p);
  return static_cast<uint64_t>(r);
}

static inline __attribute__((always_inline)) uint64_t MulShoupAReducedLocal(
    uint64_t a_in_0_2p, uint64_t b, uint64_t b_shoup, uint64_t p) {
  // reduce a from [0,2p) to [0,p) branchlessly
  uint64_t a = a_in_0_2p - (p & (0 - static_cast<uint64_t>(a_in_0_2p >= p)));
  __uint128_t q =
      (static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b_shoup)) >> 64;
  __uint128_t r =
      static_cast<__uint128_t>(a) * b - q * static_cast<__uint128_t>(p);
  return static_cast<uint64_t>(r);
}

inline __attribute__((always_inline)) void NttOperator::Butterfly(
    uint64_t &u, uint64_t &v, uint64_t w, uint64_t w_shoup) const {
  // Harvey-style forward butterfly keeping outputs in [0, 2p)
  assert(w < impl_->p.P());
  assert(impl_->p.Shoup(w) == w_shoup);
#ifdef PULSAR_NTT_STRICT_BOUNDS
  const uint64_t four_p = impl_->p_twice << 1;
  PULSAR_ASSERT_IN_RANGE(u, four_p);
  PULSAR_ASSERT_IN_RANGE(v, four_p);
#endif
  // Inputs may be in [0, 4p). Fold once into [0, 2p) cheaply.
  u = Fold2P(u, impl_->p_twice);
  v = Fold2P(v, impl_->p_twice);
#ifdef PULSAR_NTT_STRICT_BOUNDS
  PULSAR_ASSERT_IN_RANGE(u, impl_->p_twice);
  PULSAR_ASSERT_IN_RANGE(v, impl_->p_twice);
#endif
  uint64_t u_old = u;
  const uint64_t pmod = impl_->p.P();
  uint64_t t = LazyMulShoupLocal(v, w, w_shoup, pmod);  // t in [0, 2p)
#ifdef PULSAR_NTT_STRICT_BOUNDS
  PULSAR_ASSERT_IN_RANGE(t, impl_->p_twice);
#endif
  // v' = u_old + 2p - t  (mod 2p)
  uint64_t v_new = u_old + impl_->p_twice - t;
  v = Fold2P(v_new, impl_->p_twice);
  // u' = u_old + t (mod 2p)
  uint64_t u_new = u_old + t;
  u = Fold2P(u_new, impl_->p_twice);
#ifdef PULSAR_NTT_STRICT_BOUNDS
  PULSAR_ASSERT_IN_RANGE(u, impl_->p_twice);
  PULSAR_ASSERT_IN_RANGE(v, impl_->p_twice);
#endif
}

inline __attribute__((always_inline)) void NttOperator::InvButterfly(
    uint64_t &u, uint64_t &v, uint64_t zeta_inv,
    uint64_t zeta_inv_shoup) const {
#ifdef PULSAR_NTT_STRICT_BOUNDS
  const uint64_t two_p = impl_->p_twice;
  PULSAR_ASSERT_IN_RANGE(u, two_p);
  PULSAR_ASSERT_IN_RANGE(v, two_p);
#endif
  uint64_t t = impl_->p.SubVt(u, v);
  u = impl_->p.Reduce1(impl_->p.AddVt(u, v), impl_->p_twice);
  v = impl_->p.LazyMulShoup(t, zeta_inv, zeta_inv_shoup);
  v = impl_->p.Reduce1Vt(v, impl_->p.P());
#ifdef PULSAR_NTT_STRICT_BOUNDS
  PULSAR_ASSERT_IN_RANGE(u, impl_->p_twice);
  PULSAR_ASSERT_IN_RANGE(v, impl_->p.P());
#endif
}

inline __attribute__((always_inline)) void NttOperator::InvButterflyVt(
    uint64_t &u, uint64_t &v, uint64_t zeta_inv,
    uint64_t zeta_inv_shoup) const {
#ifdef PULSAR_NTT_STRICT_BOUNDS
  const uint64_t two_p = impl_->p_twice;
  PULSAR_ASSERT_IN_RANGE(u, two_p);
  PULSAR_ASSERT_IN_RANGE(v, two_p);
#endif
  uint64_t t = impl_->p.SubVt(u, v);
  u = impl_->p.Reduce1Vt(impl_->p.AddVt(u, v), impl_->p_twice);
  v = impl_->p.LazyMulShoup(t, zeta_inv, zeta_inv_shoup);
  v = impl_->p.Reduce1Vt(v, impl_->p.P());
#ifdef PULSAR_NTT_STRICT_BOUNDS
  PULSAR_ASSERT_IN_RANGE(u, impl_->p_twice);
  PULSAR_ASSERT_IN_RANGE(v, impl_->p.P());
#endif
}

inline __attribute__((always_inline)) void NttOperator::ButterflyVt(
    uint64_t &u, uint64_t &v, uint64_t zeta, uint64_t zeta_shoup) const {
#ifdef PULSAR_NTT_STRICT_BOUNDS
  const uint64_t four_p = impl_->p_twice << 1;
  PULSAR_ASSERT_IN_RANGE(u, four_p);
  PULSAR_ASSERT_IN_RANGE(v, four_p);
#endif
  // Fold inputs from [0,4p) to [0,2p) to keep invariants before mul
  u = Fold2P(u, impl_->p_twice);
  v = Fold2P(v, impl_->p_twice);
  // Shoup multiplication with a in [0, 2p); keep result lazy in [0, 2p)
  uint64_t t = LazyMulShoupLocal(v, zeta, zeta_shoup, impl_->p.P());
  // Produce outputs possibly in [0, 4p); next butterfly will fold again
  v = u + impl_->p_twice - t;
  u += t;
#ifdef PULSAR_NTT_STRICT_BOUNDS
  PULSAR_ASSERT_IN_RANGE(
      u, impl_->p_twice *
             (uint64_t)2);  // allow transient up to <4p before consumer folds
  PULSAR_ASSERT_IN_RANGE(v, impl_->p_twice * (uint64_t)2);
#endif
}

uint64_t NttOperator::PrimitiveRoot(size_t size, const zq::Modulus &p) {
  uint64_t lambda = (p.P() - 1) / (2 * size);

  // Use a deterministic method: test candidates in increasing order
  for (uint64_t candidate = 2; candidate < p.P(); ++candidate) {
    uint64_t root = p.Pow(candidate, lambda);
    if (root != 0 && IsPrimitiveRoot(root, 2 * size, p)) {
      return root;
    }
  }
  assert(false);  // Couldn't find primitive root
  return 0;
}

bool NttOperator::IsPrimitiveRoot(uint64_t a, size_t n, const zq::Modulus &p) {
  assert(a < p.P());
  return (p.Pow(a, n) == 1) && (p.Pow(a, n / 2) != 1);
}

// Harvey NTT variants (Standard Harvey-style implementation)
std::vector<uint64_t> NttOperator::ForwardHarvey(
    const std::vector<uint64_t> &input) const {
  if (!impl_->ntt_tables_.has_value()) {
    // Fall back to original implementation
    return Forward(input);
  }

  std::vector<uint64_t> a = input;
  assert(a.size() == impl_->size);

  HarveyNTT::HarveyNtt(a.data(), *impl_->ntt_tables_);
  return a;
}

std::vector<uint64_t> NttOperator::ForwardHarveyLazy(
    const std::vector<uint64_t> &input) const {
  if (!impl_->ntt_tables_.has_value()) {
    // Fall back to original lazy implementation
    return ForwardVtLazy(input);
  }

  std::vector<uint64_t> a = input;
  assert(a.size() == impl_->size);

  HarveyNTT::HarveyNttLazy(a.data(), *impl_->ntt_tables_);
  return a;
}

std::vector<uint64_t> NttOperator::BackwardHarvey(
    const std::vector<uint64_t> &input) const {
  if (!impl_->ntt_tables_.has_value()) {
    // Fall back to original implementation
    return Backward(input);
  }

  std::vector<uint64_t> a = input;
  assert(a.size() == impl_->size);

  HarveyNTT::InverseHarveyNtt(a.data(), *impl_->ntt_tables_);
  return a;
}

std::vector<uint64_t> NttOperator::BackwardHarveyLazy(
    const std::vector<uint64_t> &input) const {
  if (!impl_->ntt_tables_.has_value()) {
    // Fall back to original implementation
    return BackwardVt(input);
  }

  std::vector<uint64_t> a = input;
  assert(a.size() == impl_->size);

  HarveyNTT::InverseHarveyNttLazy(a.data(), *impl_->ntt_tables_);
  // Reduce to [0, modulus) so that lazy inverse returns canonical residues
  const uint64_t mod = impl_->p.P();
  for (auto &x : a) {
    if (x >= mod) x -= mod;
  }
  return a;
}

// Optimized variants with cache-friendly memory access
std::vector<uint64_t> NttOperator::ForwardOptimized(
    const std::vector<uint64_t> &input) const {
  if (!impl_->ntt_tables_.has_value()) {
    // Fall back to original implementation
    return Forward(input);
  }

  std::vector<uint64_t> a = input;
  assert(a.size() == impl_->size);

  OptimizedNTT::OptimizedNtt(a.data(), *impl_->ntt_tables_);
  return a;
}

std::vector<uint64_t> NttOperator::BackwardOptimized(
    const std::vector<uint64_t> &input) const {
  if (!impl_->ntt_tables_.has_value()) {
    // Fall back to original implementation
    return Backward(input);
  }

  std::vector<uint64_t> a = input;
  assert(a.size() == impl_->size);

  OptimizedNTT::InverseOptimizedNtt(a.data(), *impl_->ntt_tables_);
  return a;
}

// In-place NTT operations for performance optimization
void NttOperator::BackwardInPlace(uint64_t *data) const {
  if (impl_->ntt_tables_.has_value()) {
    HarveyNTT::InverseHarveyNtt(data, *impl_->ntt_tables_);
  } else {
    BackwardCore(data, true);
  }
}

void NttOperator::BackwardInPlaceLazy(uint64_t *data) const {
  if (impl_->ntt_tables_.has_value()) {
    HarveyNTT::InverseHarveyNttLazy(data, *impl_->ntt_tables_);
  } else {
    BackwardCore(data, false);
  }
}

void NttOperator::BackwardInPlaceLazyScaled(uint64_t *data,
                                            uint64_t scalar) const {
  if (impl_->ntt_tables_.has_value()) {
    HarveyNTT::InverseHarveyNttLazy(data, *impl_->ntt_tables_, scalar);
  } else {
    BackwardCore(data, false);
    if (scalar != 1) {
      impl_->p.ScalarMulVec(data, impl_->size, scalar);
    }
  }
}

void NttOperator::ForwardInPlace(uint64_t *data) const {
  if (impl_->ntt_tables_.has_value()) {
    HarveyNTT::HarveyNtt(data, *impl_->ntt_tables_);
  } else {
    ForwardCore(data, true);
  }
}

void NttOperator::ForwardInPlaceLazy(uint64_t *data) const {
  if (impl_->ntt_tables_.has_value()) {
    HarveyNTT::HarveyNttLazy(data, *impl_->ntt_tables_);
  } else {
    ForwardCore(data, false);
  }
}

// Access to internal NTT tables for direct Harvey NTT usage
const NTTTables *NttOperator::GetNTTTables() const {
  if (impl_->ntt_tables_.has_value()) {
    return &(*impl_->ntt_tables_);
  }
  return nullptr;
}

}  // namespace ntt
}  // namespace math
}  // namespace bfv
