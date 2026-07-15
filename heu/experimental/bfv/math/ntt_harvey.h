#ifndef NTT_HARVEY_H
#define NTT_HARVEY_H

#include <cstdint>
#include <vector>

#include "math/modulus.h"
#include "math/ntt_tables.h"

namespace bfv {
namespace math {
namespace ntt {

/**
 * Harvey NTT implementation optimized for modular arithmetic performance.
 * Provides both lazy and non-lazy variants of forward and inverse NTT.
 */
class HarveyNTT {
 public:
  /**
   * Forward NTT with lazy reduction (Harvey butterfly operations).
   * Outputs remain in a lazy range bounded by [0, 4*modulus). Callers that
   * chain directly into a lazy inverse must first normalize back to
   * [0, 2*modulus).
   */
  static void HarveyNttLazy(std::uint64_t *operand, const NTTTables &tables);

  /**
   * Forward NTT with full reduction (Harvey butterfly operations).
   * Outputs are in [0, modulus) range.
   */
  static void HarveyNtt(std::uint64_t *operand, const NTTTables &tables);

  /**
   * Four-way forward NTT with full reduction.
   * Applies the same transform to four operands sharing the same tables.
   */
  static void HarveyNtt4(std::uint64_t *operand0, std::uint64_t *operand1,
                         std::uint64_t *operand2, std::uint64_t *operand3,
                         const NTTTables &tables);

  /**
   * Four-way forward NTT with lazy reduction.
   * Outputs are kept in the lazy range and skip the final normalization pass.
   */
  static void HarveyNttLazy4(std::uint64_t *operand0, std::uint64_t *operand1,
                             std::uint64_t *operand2, std::uint64_t *operand3,
                             const NTTTables &tables);

  /**
   * Inverse NTT with lazy reduction (Harvey butterfly operations).
   * Expects NTT coefficients already normalized to [0, 2*modulus) and
   * returns power-basis coefficients in the same lazy range.
   */
  static void InverseHarveyNttLazy(std::uint64_t *operand,
                                   const NTTTables &tables,
                                   std::uint64_t scalar = 1);

  /**
   * Three-way inverse NTT with lazy reduction.
   * Applies the same transform to three operands sharing the same tables.
   */
  static void InverseHarveyNttLazy3(std::uint64_t *operand0,
                                    std::uint64_t *operand1,
                                    std::uint64_t *operand2,
                                    const NTTTables &tables);

  /**
   * Two-way inverse NTT with full reduction.
   * Applies the same transform to two operands sharing the same tables.
   */
  static void InverseHarveyNtt2(std::uint64_t *operand0,
                                std::uint64_t *operand1,
                                const NTTTables &tables);

  /**
   * Two-way inverse NTT with lazy reduction.
   * Outputs are in [0, 2*modulus) range.
   */
  static void InverseHarveyNttLazy2(std::uint64_t *operand0,
                                    std::uint64_t *operand1,
                                    const NTTTables &tables);

  /**
   * Inverse NTT with full reduction (Harvey butterfly operations).
   * Outputs are in [0, modulus) range.
   */
  static void InverseHarveyNtt(std::uint64_t *operand, const NTTTables &tables);

 private:
  // Harvey butterfly operation for forward NTT (lazy reduction)
  static inline void HarveyButterflyLazy(std::uint64_t &u, std::uint64_t &v,
                                         const zq::MultiplyUIntModOperand &root,
                                         std::uint64_t modulus);

  // Harvey butterfly operation for forward NTT (full reduction)
  static inline void HarveyButterfly(std::uint64_t &u, std::uint64_t &v,
                                     const zq::MultiplyUIntModOperand &root,
                                     std::uint64_t modulus);

  // Harvey inverse butterfly operation (lazy reduction)
  static inline void InverseHarveyButterflyLazy(
      std::uint64_t &u, std::uint64_t &v,
      const zq::MultiplyUIntModOperand &inv_root, std::uint64_t modulus);

  // Harvey inverse butterfly operation (full reduction)
  static inline void InverseHarveyButterfly(
      std::uint64_t &u, std::uint64_t &v,
      const zq::MultiplyUIntModOperand &inv_root, std::uint64_t modulus);
};

/**
 * Arithmetic template class for lazy modular arithmetic operations.
 * Provides guard functions and lazy reduction utilities.
 */
template <typename T>
class Arithmetic {
 public:
  /**
   * Guard function to handle values in [0, 2*modulus) range.
   * Reduces to [0, modulus) if needed.
   */
  static inline T Guard(T value, T modulus) {
    return value >= modulus ? value - modulus : value;
  }

  /**
   * Guard function to handle values that may be >= 2*modulus.
   * Reduces to [0, modulus) range.
   */
  static inline T GuardFull(T value, T modulus) { return value % modulus; }

  /**
   * Lazy addition that may produce results in [0, 2*modulus) range.
   */
  static inline T AddLazy(T a, T b, T modulus) {
    T result = a + b;
    return result >= (modulus << 1) ? result - (modulus << 1) : result;
  }

  /**
   * Lazy subtraction that may produce results in [0, 2*modulus) range.
   */
  static inline T SubLazy(T a, T b, T modulus) {
    return a >= b ? a - b : a + (modulus << 1) - b;
  }

  /**
   * Full reduction from any range to [0, modulus).
   */
  static inline T Reduce(T value, T modulus) { return value % modulus; }
};

}  // namespace ntt
}  // namespace math
}  // namespace bfv

#endif  // NTT_HARVEY_H
