#include "math/ntt_optimized.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>

#include "math/ntt_harvey.h"

namespace bfv {
namespace math {
namespace ntt {

// Local bit reversal function
static inline size_t ReverseBitsLocal(size_t value, size_t bit_count) {
  size_t result = 0;
  for (size_t i = 0; i < bit_count; ++i) {
    result = (result << 1) | (value & 1);
    value >>= 1;
  }
  return result;
}

// Local Harvey butterfly operations (copied from HarveyNTT for access)
static inline std::uint64_t MulUintModLocal(
    std::uint64_t operand, const zq::MultiplyUIntModOperand &mod_operand,
    std::uint64_t modulus) {
  // Harvey's method: compute high part of operand * quotient
  __uint128_t wide_quotient =
      static_cast<__uint128_t>(operand) * mod_operand.quotient;
  std::uint64_t quotient_high = static_cast<std::uint64_t>(wide_quotient >> 64);

  // Compute result = operand * mod_operand.operand - quotient_high * modulus
  __uint128_t wide_product =
      static_cast<__uint128_t>(operand) * mod_operand.operand;
  __uint128_t wide_correction =
      static_cast<__uint128_t>(quotient_high) * modulus;

  std::uint64_t result =
      static_cast<std::uint64_t>(wide_product - wide_correction);

  // Reduce to [0, modulus)
  return result >= modulus ? result - modulus : result;
}

static inline void HarveyButterflyLocal(std::uint64_t &u, std::uint64_t &v,
                                        const zq::MultiplyUIntModOperand &root,
                                        std::uint64_t modulus) {
  // Reduce inputs to [0, modulus) first
  u = Arithmetic<std::uint64_t>::Guard(u, modulus);
  v = Arithmetic<std::uint64_t>::Guard(v, modulus);

  // Compute t = v * root (full multiplication)
  std::uint64_t t = MulUintModLocal(v, root, modulus);

  // u' = (u + t) mod modulus
  std::uint64_t u_new = (u + t >= modulus) ? u + t - modulus : u + t;

  // v' = (u + modulus - t) mod modulus
  std::uint64_t v_new = (u >= t) ? u - t : u + modulus - t;

  u = u_new;
  v = v_new;
}

static inline void InverseHarveyButterflyLocal(
    std::uint64_t &u, std::uint64_t &v,
    const zq::MultiplyUIntModOperand &inv_root, std::uint64_t modulus) {
  // Reduce inputs to [0, modulus) first
  u = Arithmetic<std::uint64_t>::Guard(u, modulus);
  v = Arithmetic<std::uint64_t>::Guard(v, modulus);

  // t = (u + v) mod modulus
  std::uint64_t t = (u + v >= modulus) ? u + v - modulus : u + v;

  // d = (u + modulus - v) mod modulus
  std::uint64_t d = (u >= v) ? u - v : u + modulus - v;

  // u' = t
  u = t;

  // v' = d * inv_root (full multiplication)
  v = MulUintModLocal(d, inv_root, modulus);
}

struct CacheOptimizedNTTTables::Impl {
  std::vector<std::uint64_t> root_powers_flat_;
  std::vector<std::uint64_t> root_quotients_flat_;
  std::vector<std::uint64_t> inv_root_powers_flat_;
  std::vector<std::uint64_t> inv_root_quotients_flat_;
  size_t coeff_count_;
  zq::Modulus modulus_;

  Impl(const NTTTables &tables)
      : coeff_count_(tables.GetCoeffCount()), modulus_(tables.GetModulus()) {
    const auto &root_powers = tables.GetRootPowers();
    const auto &inv_root_powers = tables.GetInvRootPowers();

    // Flatten MultiplyUIntModOperand arrays for better cache performance
    root_powers_flat_.reserve(coeff_count_);
    root_quotients_flat_.reserve(coeff_count_);
    inv_root_powers_flat_.reserve(coeff_count_);
    inv_root_quotients_flat_.reserve(coeff_count_);

    for (size_t i = 0; i < coeff_count_; ++i) {
      root_powers_flat_.push_back(root_powers[i].operand);
      root_quotients_flat_.push_back(root_powers[i].quotient);
      inv_root_powers_flat_.push_back(inv_root_powers[i].operand);
      inv_root_quotients_flat_.push_back(inv_root_powers[i].quotient);
    }
  }
};

CacheOptimizedNTTTables::CacheOptimizedNTTTables(const NTTTables &tables)
    : impl_(std::make_unique<Impl>(tables)) {}

CacheOptimizedNTTTables::~CacheOptimizedNTTTables() = default;

const std::uint64_t *CacheOptimizedNTTTables::GetRootPowersFlat() const {
  return impl_->root_powers_flat_.data();
}

const std::uint64_t *CacheOptimizedNTTTables::GetRootQuotientsFlat() const {
  return impl_->root_quotients_flat_.data();
}

const std::uint64_t *CacheOptimizedNTTTables::GetInvRootPowersFlat() const {
  return impl_->inv_root_powers_flat_.data();
}

const std::uint64_t *CacheOptimizedNTTTables::GetInvRootQuotientsFlat() const {
  return impl_->inv_root_quotients_flat_.data();
}

size_t CacheOptimizedNTTTables::GetCoeffCount() const {
  return impl_->coeff_count_;
}

const zq::Modulus &CacheOptimizedNTTTables::GetModulus() const {
  return impl_->modulus_;
}

void OptimizedNTT::OptimizedNtt(std::uint64_t *operand,
                                const NTTTables &tables) {
  const size_t coeff_count = tables.GetCoeffCount();
  const std::uint64_t modulus = tables.GetModulus().P();

  // Create cache-optimized table layout
  CacheOptimizedNTTTables opt_tables(tables);
  const std::uint64_t *root_ops = opt_tables.GetRootPowersFlat();
  const std::uint64_t *root_quots = opt_tables.GetRootQuotientsFlat();

  // Ensure memory alignment for SIMD operations
  bool is_simd_aligned = is_aligned(operand, 32);  // AVX2 alignment

  // Use sequential indexing pattern
  size_t l = coeff_count >> 1;
  size_t m = 1;
  size_t root_idx = 0;

  while (l > 0) {
    for (size_t i = 0; i < m; ++i) {
      // Create MultiplyUIntModOperand from flattened arrays
      zq::MultiplyUIntModOperand root;
      root.operand = root_ops[++root_idx];
      root.quotient = root_quots[root_idx];

      size_t s = 2 * i * l;
      std::uint64_t *u_ptr = operand + s;
      std::uint64_t *v_ptr = u_ptr + l;

      // Choose optimization strategy based on gap size and alignment
      if (l >= SIMD_WIDTH && is_simd_aligned) {
#ifdef __AVX2__
        butterfly_avx2_block(u_ptr, v_ptr, root, modulus, l);
#else
        butterfly_prefetch_block(u_ptr, v_ptr, root, modulus, l,
                                 PREFETCH_DISTANCE);
#endif
      } else if (l >= PREFETCH_DISTANCE) {
        butterfly_prefetch_block(u_ptr, v_ptr, root, modulus, l,
                                 PREFETCH_DISTANCE);
      } else {
        // Small gaps: use simple loop without prefetching
        for (size_t j = 0; j < l; ++j) {
          HarveyButterflyLocal(u_ptr[j], v_ptr[j], root, modulus);
        }
      }
    }
    l >>= 1;
    m <<= 1;
  }
}

void OptimizedNTT::InverseOptimizedNtt(std::uint64_t *operand,
                                       const NTTTables &tables) {
  const size_t coeff_count = tables.GetCoeffCount();
  const std::uint64_t modulus = tables.GetModulus().P();

  // Create cache-optimized table layout
  CacheOptimizedNTTTables opt_tables(tables);
  const std::uint64_t *inv_root_ops = opt_tables.GetInvRootPowersFlat();
  const std::uint64_t *inv_root_quots = opt_tables.GetInvRootQuotientsFlat();

  bool is_simd_aligned = is_aligned(operand, 32);

  // Use same indexing pattern as original inverse NTT
  size_t m = coeff_count >> 1;
  size_t l = 1;
  // Consume inverse roots in scrambled sequential order (skip index 0 which is
  // 1)
  size_t root_idx = 0;

  while (m > 0) {
    for (size_t i = 0; i < m; ++i) {
      // Create MultiplyUIntModOperand from flattened arrays
      zq::MultiplyUIntModOperand inv_root;
      inv_root.operand = inv_root_ops[++root_idx];
      inv_root.quotient = inv_root_quots[root_idx];

      size_t s = 2 * i * l;
      std::uint64_t *u_ptr = operand + s;
      std::uint64_t *v_ptr = u_ptr + l;

      // Apply same optimization strategy as forward NTT
      if (l >= SIMD_WIDTH && is_simd_aligned) {
#ifdef __AVX2__
        inverse_butterfly_avx2_block(u_ptr, v_ptr, inv_root, modulus, l);
#else
        // Use inverse butterfly operations
        for (size_t j = 0; j < l; ++j) {
          InverseHarveyButterflyLocal(u_ptr[j], v_ptr[j], inv_root, modulus);
        }
#endif
      } else if (l >= PREFETCH_DISTANCE) {
        // Prefetch-optimized inverse butterflies
        for (size_t j = 0; j < l; j += PREFETCH_DISTANCE) {
          size_t end = std::min(j + PREFETCH_DISTANCE, l);

          // Prefetch next block
          if (end < l) {
            __builtin_prefetch(&u_ptr[end], 1, 3);
            __builtin_prefetch(&v_ptr[end], 1, 3);
          }

          // Process current block
          for (size_t kk = j; kk < end; ++kk) {
            InverseHarveyButterflyLocal(u_ptr[kk], v_ptr[kk], inv_root,
                                        modulus);
          }
        }
      } else {
        // Small gaps: simple loop
        for (size_t j = 0; j < l; ++j) {
          InverseHarveyButterflyLocal(u_ptr[j], v_ptr[j], inv_root, modulus);
        }
      }
    }
    // Advance to next stage
    l <<= 1;
    m >>= 1;
  }

  // Scale by inverse of n
  const auto &inv_n = tables.GetInvDegreeModulo();
  for (size_t i = 0; i < coeff_count; ++i) {
    operand[i] = MulUintModLocal(operand[i], inv_n, modulus);
  }
}

void OptimizedNTT::BitReverseCopyOptimized(const std::uint64_t *src,
                                           std::uint64_t *dst, size_t size) {
  size_t log_n = static_cast<size_t>(std::log2(size));

  // Cache-friendly bit-reversal using block-based approach
  constexpr size_t BLOCK_SIZE = CACHE_LINE_SIZE / sizeof(std::uint64_t);

  for (size_t block = 0; block < size; block += BLOCK_SIZE) {
    size_t block_end = std::min(block + BLOCK_SIZE, size);

    // Prefetch destination block
    for (size_t i = block; i < block_end;
         i += CACHE_LINE_SIZE / sizeof(std::uint64_t)) {
      size_t rev_i = ReverseBitsLocal(i, log_n);
      __builtin_prefetch(&dst[rev_i], 1, 3);
    }

    // Process block
    for (size_t i = block; i < block_end; ++i) {
      size_t rev_i = ReverseBitsLocal(i, log_n);
      dst[rev_i] = src[i];
    }
  }
}

void OptimizedNTT::BitReverseInplaceOptimized(std::uint64_t *data,
                                              size_t size) {
  size_t log_n = static_cast<size_t>(std::log2(size));

  // In-place bit-reversal with cache-friendly swapping
  for (size_t i = 0; i < size; ++i) {
    size_t rev_i = ReverseBitsLocal(i, log_n);

    if (i < rev_i) {
      // Prefetch both locations
      __builtin_prefetch(&data[i], 1, 3);
      __builtin_prefetch(&data[rev_i], 1, 3);

      // Swap
      std::swap(data[i], data[rev_i]);
    }
  }
}

#ifdef __AVX2__
#include <immintrin.h>

// Helper for modular addition: (a + b) mod p
// Assumes a, b < p and p < 2^63
static inline __m256i add_mod_avx2(__m256i a, __m256i b, __m256i p) {
  __m256i sum = _mm256_add_epi64(a, b);
  __m256i diff = _mm256_sub_epi64(sum, p);
  // If sum >= p, diff is non-negative (top bit 0), so we use diff.
  // However, cmpgt checks signed greater.
  // p < 2^63, so if no overflow in sum (sum < 2^64), and sum < 2p < 2^64
  // (likely checked by caller bounds) For safety with signed compare, p should
  // be < 2^63. If sum >= p, then we want to select diff. We can use
  // _mm256_cmpgt_epi64(sum, p_minus_1)
  __m256i p_minus_1 = _mm256_sub_epi64(p, _mm256_set1_epi64x(1));
  __m256i mask = _mm256_cmpgt_epi64(
      sum, p_minus_1);  // 0xFF.. if sum > p-1 (i.e. sum >= p)
  return _mm256_blendv_epi8(sum, diff, mask);
}

// Helper for modular subtraction: (a - b) mod p
// Assumes a, b < p
static inline __m256i sub_mod_avx2(__m256i a, __m256i b, __m256i p) {
  __m256i diff = _mm256_sub_epi64(a, b);
  // If a >= b, diff >= 0, we use diff.
  // If a < b, diff is negative (in 2's complement), top bit 1?
  // Wait, simple sub wrapper:
  // mask = (a < b) ? 0xFF : 0;
  // result = diff + (mask & p);
  // a < b check: use _mm256_cmpgt_epi64(b, a)
  __m256i mask = _mm256_cmpgt_epi64(b, a);
  __m256i add_p = _mm256_and_si256(mask, p);
  return _mm256_add_epi64(diff, add_p);
}

inline void OptimizedNTT::inverse_butterfly_avx2_block(
    std::uint64_t *u_ptr, std::uint64_t *v_ptr,
    const zq::MultiplyUIntModOperand &root, std::uint64_t modulus,
    size_t count) {
  // Process 4 elements at a time with AVX2
  size_t simd_count = (count / SIMD_WIDTH) * SIMD_WIDTH;

  __m256i p_vec = _mm256_set1_epi64x(modulus);
  // root is inv_root here

  for (size_t i = 0; i < simd_count; i += SIMD_WIDTH) {
    // Prefetch next iteration
    if (i + SIMD_WIDTH < simd_count) {
      __builtin_prefetch(&u_ptr[i + SIMD_WIDTH], 1, 3);
      __builtin_prefetch(&v_ptr[i + SIMD_WIDTH], 1, 3);
    }

    // 1. Load u and v vectors
    __m256i u_vec =
        _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&u_ptr[i]));
    __m256i v_vec =
        _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&v_ptr[i]));

    // 2. Vectorized arithmetic
    // t = (u + v) mod p
    __m256i t_vec = add_mod_avx2(u_vec, v_vec, p_vec);

    // d = (u - v) mod p
    __m256i d_vec = sub_mod_avx2(u_vec, v_vec, p_vec);

    // 3. Store u' = t
    _mm256_storeu_si256(reinterpret_cast<__m256i *>(&u_ptr[i]), t_vec);

    // 4. Compute v' = d * inv_root
    // Extract d lanes
    uint64_t d0 = _mm256_extract_epi64(d_vec, 0);
    uint64_t d1 = _mm256_extract_epi64(d_vec, 1);
    uint64_t d2 = _mm256_extract_epi64(d_vec, 2);
    uint64_t d3 = _mm256_extract_epi64(d_vec, 3);

    // Scalar multiplication
    uint64_t v0 = MulUintModLocal(d0, root, modulus);
    uint64_t v1 = MulUintModLocal(d1, root, modulus);
    uint64_t v2 = MulUintModLocal(d2, root, modulus);
    uint64_t v3 = MulUintModLocal(d3, root, modulus);

    // Rebuild v' vector
    __m256i v_new = _mm256_set_epi64x(v3, v2, v1, v0);

    // Store v'
    _mm256_storeu_si256(reinterpret_cast<__m256i *>(&v_ptr[i]), v_new);
  }

  // Handle remaining elements
  for (size_t i = simd_count; i < count; ++i) {
    InverseHarveyButterflyLocal(u_ptr[i], v_ptr[i], root, modulus);
  }
}
#endif

#ifdef __AVX2__
inline void OptimizedNTT::butterfly_avx2_block(
    std::uint64_t *u_ptr, std::uint64_t *v_ptr,
    const zq::MultiplyUIntModOperand &root, std::uint64_t modulus,
    size_t count) {
  // Process 4 elements at a time with AVX2
  size_t simd_count = (count / SIMD_WIDTH) * SIMD_WIDTH;

  __m256i p_vec = _mm256_set1_epi64x(modulus);
  // root.operand and quotient are scalars used in the scalar mul loop

  for (size_t i = 0; i < simd_count; i += SIMD_WIDTH) {
    // Prefetch next iteration
    if (i + SIMD_WIDTH < simd_count) {
      __builtin_prefetch(&u_ptr[i + SIMD_WIDTH], 1, 3);
      __builtin_prefetch(&v_ptr[i + SIMD_WIDTH], 1, 3);
    }

    // 1. Load u and v vectors
    __m256i u_vec =
        _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&u_ptr[i]));
    __m256i v_vec =
        _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&v_ptr[i]));

    // 2. Perform scalar modular multiplication for t = v * root
    // We extract lanes, compute, and rebuild the vector.
    // This avoids implementing 64x64->128 arithmetic in full AVX2 which is
    // inefficient. The latency of moving to scalar and back is often hidden by
    // the high-latency multiply.

    // Extract v lanes
    uint64_t v0 = _mm256_extract_epi64(v_vec, 0);
    uint64_t v1 = _mm256_extract_epi64(v_vec, 1);
    uint64_t v2 = _mm256_extract_epi64(v_vec, 2);
    uint64_t v3 = _mm256_extract_epi64(v_vec, 3);

    // Scalar multiplication
    uint64_t t0 = MulUintModLocal(v0, root, modulus);
    uint64_t t1 = MulUintModLocal(v1, root, modulus);
    uint64_t t2 = MulUintModLocal(v2, root, modulus);
    uint64_t t3 = MulUintModLocal(v3, root, modulus);

    // Rebuild t vector
    __m256i t_vec = _mm256_set_epi64x(t3, t2, t1, t0);

    // 3. Vectorized butterfly arithmetic
    // u' = (u + t) mod p
    __m256i u_new = add_mod_avx2(u_vec, t_vec, p_vec);

    // v' = (u - t) mod p -> (u + (p-t)) mod p?
    // Standard formula: v' = (u >= t) ? u - t : u + p - t;
    // This is exactly sub_mod_avx2(u, t, p)
    __m256i v_new = sub_mod_avx2(u_vec, t_vec, p_vec);

    // 4. Store
    _mm256_storeu_si256(reinterpret_cast<__m256i *>(&u_ptr[i]), u_new);
    _mm256_storeu_si256(reinterpret_cast<__m256i *>(&v_ptr[i]), v_new);
  }

  // Handle remaining elements with scalar loop
  for (size_t i = simd_count; i < count; ++i) {
    HarveyButterflyLocal(u_ptr[i], v_ptr[i], root, modulus);
  }
}
#endif

inline void OptimizedNTT::butterfly_prefetch_block(
    std::uint64_t *u_ptr, std::uint64_t *v_ptr,
    const zq::MultiplyUIntModOperand &root, std::uint64_t modulus, size_t count,
    size_t prefetch_distance) {
  for (size_t i = 0; i < count; i += prefetch_distance) {
    size_t end = std::min(i + prefetch_distance, count);

    // Prefetch next block
    if (end < count) {
      __builtin_prefetch(&u_ptr[end], 1, 3);
      __builtin_prefetch(&v_ptr[end], 1, 3);
    }

    // Process current block
    for (size_t j = i; j < end; ++j) {
      HarveyButterflyLocal(u_ptr[j], v_ptr[j], root, modulus);
    }
  }
}

}  // namespace ntt
}  // namespace math
}  // namespace bfv
