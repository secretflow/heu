#ifndef NTT_OPTIMIZED_H
#define NTT_OPTIMIZED_H

#include <cstdint>
#include <vector>
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

#include "math/modulus.h"
#include "math/ntt_tables.h"

namespace bfv {
namespace math {
namespace ntt {

/**
 * Optimized NTT implementation with cache-friendly memory access patterns,
 * SIMD vectorization, and memory prefetching.
 */
class OptimizedNTT {
 public:
  /**
   * Cache-friendly forward NTT with memory prefetching and SIMD optimization.
   */
  static void OptimizedNtt(std::uint64_t *operand, const NTTTables &tables);

  /**
   * Cache-friendly inverse NTT with memory prefetching and SIMD optimization.
   */
  static void InverseOptimizedNtt(std::uint64_t *operand,
                                  const NTTTables &tables);

  /**
   * Optimized bit-reversal with better cache locality.
   */
  static void BitReverseCopyOptimized(const std::uint64_t *src,
                                      std::uint64_t *dst, size_t size);

  /**
   * In-place bit-reversal with cache-friendly access pattern.
   */
  static void BitReverseInplaceOptimized(std::uint64_t *data, size_t size);

  // Memory alignment utilities (public for testing)
  static inline bool is_aligned(const void *ptr, size_t alignment) {
    return reinterpret_cast<uintptr_t>(ptr) % alignment == 0;
  }

  static inline void *align_pointer(void *ptr, size_t alignment) {
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    uintptr_t aligned = (addr + alignment - 1) & ~(alignment - 1);
    return reinterpret_cast<void *>(aligned);
  }

 private:
// SIMD-optimized butterfly operations
#ifdef __AVX2__
  static inline void butterfly_avx2_block(
      std::uint64_t *u_ptr, std::uint64_t *v_ptr,
      const zq::MultiplyUIntModOperand &root, std::uint64_t modulus,
      size_t count);

  static inline void inverse_butterfly_avx2_block(
      std::uint64_t *u_ptr, std::uint64_t *v_ptr,
      const zq::MultiplyUIntModOperand &root, std::uint64_t modulus,
      size_t count);
#endif

  // Cache-friendly butterfly with prefetching
  static inline void butterfly_prefetch_block(
      std::uint64_t *u_ptr, std::uint64_t *v_ptr,
      const zq::MultiplyUIntModOperand &root, std::uint64_t modulus,
      size_t count, size_t prefetch_distance);

  // Prefetch constants
  static constexpr size_t CACHE_LINE_SIZE = 64;
  static constexpr size_t PREFETCH_DISTANCE = 8;
  static constexpr size_t SIMD_WIDTH =
      4;  // Number of uint64_t per AVX2 register
};

/**
 * Memory-optimized NTT table layout for better cache performance.
 */
class CacheOptimizedNTTTables {
 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;

 public:
  CacheOptimizedNTTTables(const NTTTables &tables);
  ~CacheOptimizedNTTTables();

  // Accessors for cache-optimized data layout
  const std::uint64_t *GetRootPowersFlat() const;
  const std::uint64_t *GetRootQuotientsFlat() const;
  const std::uint64_t *GetInvRootPowersFlat() const;
  const std::uint64_t *GetInvRootQuotientsFlat() const;

  size_t GetCoeffCount() const;
  const zq::Modulus &GetModulus() const;
};

}  // namespace ntt
}  // namespace math
}  // namespace bfv

#endif  // NTT_OPTIMIZED_H
