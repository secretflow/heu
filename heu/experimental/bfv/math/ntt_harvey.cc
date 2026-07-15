#include "math/ntt_harvey.h"

#include <cassert>
#include <cmath>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

namespace bfv {
namespace math {
namespace ntt {

static inline __attribute__((always_inline)) std::uint64_t Mul64HighLocal(
    std::uint64_t x, std::uint64_t y) {
#if defined(__BMI2__)
  std::uint64_t hi;
  _mulx_u64(x, y, reinterpret_cast<unsigned long long *>(&hi));
  return hi;
#else
  return static_cast<std::uint64_t>((static_cast<__uint128_t>(x) * y) >> 64);
#endif
}

// Helper functions for optimized modular arithmetic
static inline __attribute__((always_inline)) std::uint64_t MulUintModLazy(
    std::uint64_t operand, const zq::MultiplyUIntModOperand &mod_operand,
    std::uint64_t modulus) {
  std::uint64_t quotient_high = Mul64HighLocal(operand, mod_operand.quotient);
  return (operand * mod_operand.operand) - (quotient_high * modulus);
}

static inline __attribute__((always_inline)) std::uint64_t MulUintMod(
    std::uint64_t operand, const zq::MultiplyUIntModOperand &mod_operand,
    std::uint64_t modulus) {
  std::uint64_t result = MulUintModLazy(operand, mod_operand, modulus);
  return (result >= modulus) ? result - modulus : result;
}

// Modular arithmetic operations
static inline __attribute__((always_inline)) std::uint64_t GuardLazy(
    std::uint64_t a, std::uint64_t two_times_modulus) {
  return (a >= two_times_modulus) ? a - two_times_modulus : a;
}

static inline __attribute__((always_inline)) std::uint64_t AddLazy(
    std::uint64_t a, std::uint64_t b, std::uint64_t) {
  return a + b;
}

static inline __attribute__((always_inline)) std::uint64_t SubLazy(
    std::uint64_t a, std::uint64_t b, std::uint64_t two_times_modulus) {
  return a + two_times_modulus - b;
}

void HarveyNTT::HarveyNttLazy(std::uint64_t *operand, const NTTTables &tables) {
  const size_t coeff_count = tables.GetCoeffCount();
  const auto *roots = tables.GetRootPowers().data();
  const std::uint64_t modulus = tables.GetModulus().P();
  const std::uint64_t two_times_modulus = modulus << 1;

  // Optimized forward NTT implementation
  size_t gap = coeff_count >> 1;
  size_t m = 1;

  // Main NTT loop with structural optimizations
  for (; m < (coeff_count >> 1); m <<= 1) {
    size_t offset = 0;

    if (gap < 4) {
      // Small gap: no unrolling
      for (size_t i = 0; i < m; ++i) {
        const auto &root = *++roots;
        std::uint64_t *x = operand + offset;
        std::uint64_t *y = x + gap;

        for (size_t j = 0; j < gap; ++j) {
          std::uint64_t u = GuardLazy(*x, two_times_modulus);
          std::uint64_t v = MulUintModLazy(*y, root, modulus);
          *x++ = AddLazy(u, v, two_times_modulus);
          *y++ = SubLazy(u, v, two_times_modulus);
        }
        offset += gap << 1;
      }
    } else {
      // Large gap: 4-way unrolling for better pipeline utilization
      for (size_t i = 0; i < m; ++i) {
        const auto &root = *++roots;
        std::uint64_t *x = operand + offset;
        std::uint64_t *y = x + gap;

        for (size_t j = 0; j < gap; j += 4) {
          // Unroll 4 iterations
          std::uint64_t u = GuardLazy(*x, two_times_modulus);
          std::uint64_t v = MulUintModLazy(*y, root, modulus);
          *x++ = AddLazy(u, v, two_times_modulus);
          *y++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x, two_times_modulus);
          v = MulUintModLazy(*y, root, modulus);
          *x++ = AddLazy(u, v, two_times_modulus);
          *y++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x, two_times_modulus);
          v = MulUintModLazy(*y, root, modulus);
          *x++ = AddLazy(u, v, two_times_modulus);
          *y++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x, two_times_modulus);
          v = MulUintModLazy(*y, root, modulus);
          *x++ = AddLazy(u, v, two_times_modulus);
          *y++ = SubLazy(u, v, two_times_modulus);
        }
        offset += gap << 1;
      }
    }
    gap >>= 1;
  }

  // Final stage
  std::uint64_t *values = operand;
  for (size_t i = 0; i < m; ++i) {
    const auto &root = *++roots;
    std::uint64_t u = GuardLazy(values[0], two_times_modulus);
    std::uint64_t v = MulUintModLazy(values[1], root, modulus);
    values[0] = AddLazy(u, v, two_times_modulus);
    values[1] = SubLazy(u, v, two_times_modulus);
    values += 2;
  }
}

void HarveyNTT::HarveyNtt(std::uint64_t *operand, const NTTTables &tables) {
  // First do lazy NTT
  HarveyNttLazy(operand, tables);

  // Then reduce all coefficients from [0, 4*modulus) to [0, modulus)
  // Reducing once at the end is more efficient than reducing in each butterfly
  const std::uint64_t modulus = tables.GetModulus().P();
  const std::uint64_t two_times_modulus = modulus << 1;
  const size_t n = tables.GetCoeffCount();

  for (size_t i = 0; i < n; ++i) {
    // Reduction: first check >= 2*modulus, then >= modulus
    std::uint64_t v = operand[i];
    v = (v >= two_times_modulus) ? v - two_times_modulus : v;
    v = (v >= modulus) ? v - modulus : v;
    operand[i] = v;
  }
}

void HarveyNTT::InverseHarveyNttLazy(std::uint64_t *operand,
                                     const NTTTables &tables,
                                     std::uint64_t scalar) {
  const size_t coeff_count = tables.GetCoeffCount();
  const auto *roots = tables.GetInvRootPowers().data();
  const std::uint64_t modulus = tables.GetModulus().P();
  const std::uint64_t two_times_modulus = modulus << 1;

  // Optimized inverse NTT implementation
  size_t gap = 1;
  size_t m = coeff_count >> 1;

  // Main inverse NTT loop with optimizations
  for (; m > 1; m >>= 1) {
    size_t offset = 0;

    if (gap < 4) {
      // Small gap: no unrolling
      for (size_t i = 0; i < m; ++i) {
        const auto &inv_root = *++roots;
        std::uint64_t *x = operand + offset;
        std::uint64_t *y = x + gap;

        for (size_t j = 0; j < gap; ++j) {
          std::uint64_t u = *x;
          std::uint64_t v = *y;
          std::uint64_t sum = AddLazy(u, v, two_times_modulus);
          std::uint64_t diff = SubLazy(u, v, two_times_modulus);
          *x++ = GuardLazy(sum, two_times_modulus);
          *y++ = MulUintModLazy(diff, inv_root, modulus);
        }
        offset += gap << 1;
      }
    } else {
      // Large gap: 4-way unrolling for better pipeline utilization
      for (size_t i = 0; i < m; ++i) {
        const auto &inv_root = *++roots;
        std::uint64_t *x = operand + offset;
        std::uint64_t *y = x + gap;

        for (size_t j = 0; j < gap; j += 4) {
          // Unroll 4 iterations
          std::uint64_t u = *x;
          std::uint64_t v = *y;
          std::uint64_t sum = AddLazy(u, v, two_times_modulus);
          std::uint64_t diff = SubLazy(u, v, two_times_modulus);
          *x++ = GuardLazy(sum, two_times_modulus);
          *y++ = MulUintModLazy(diff, inv_root, modulus);

          u = *x;
          v = *y;
          sum = AddLazy(u, v, two_times_modulus);
          diff = SubLazy(u, v, two_times_modulus);
          *x++ = GuardLazy(sum, two_times_modulus);
          *y++ = MulUintModLazy(diff, inv_root, modulus);

          u = *x;
          v = *y;
          sum = AddLazy(u, v, two_times_modulus);
          diff = SubLazy(u, v, two_times_modulus);
          *x++ = GuardLazy(sum, two_times_modulus);
          *y++ = MulUintModLazy(diff, inv_root, modulus);

          u = *x;
          v = *y;
          sum = AddLazy(u, v, two_times_modulus);
          diff = SubLazy(u, v, two_times_modulus);
          *x++ = GuardLazy(sum, two_times_modulus);
          *y++ = MulUintModLazy(diff, inv_root, modulus);
        }
        offset += gap << 1;
      }
    }
    gap <<= 1;
  }

  // Final stage with scaling by inverse of n; optionally fuse an extra scalar
  // multiplication. This matches DWTHandler's scalar path in spirit and avoids
  // a separate pass over coefficients when callers need a post-INTT scalar.
  const auto &inv_n = tables.GetInvDegreeModulo();
  std::uint64_t inv_n_operand = inv_n.operand;
  if (scalar != 1) {
    std::uint64_t scalar_mod = scalar;
    if (scalar_mod >= modulus) {
      scalar_mod %= modulus;
    }
    zq::MultiplyUIntModOperand scalar_operand;
    scalar_operand.set(scalar_mod, modulus);
    inv_n_operand = MulUintMod(inv_n_operand, scalar_operand, modulus);
  }
  zq::MultiplyUIntModOperand inv_n_scaled;
  inv_n_scaled.set(inv_n_operand, modulus);
  const auto &inv_root = *++roots;

  // Create scaled root for better performance
  // We need to multiply inv_root by (inv_n * scalar) to get scaled_inv_root.
  std::uint64_t temp_product =
      MulUintMod(inv_root.operand, inv_n_scaled, modulus);
  zq::MultiplyUIntModOperand scaled_inv_root;
  scaled_inv_root.set(temp_product, modulus);

  std::uint64_t *x = operand;
  std::uint64_t *y = x + gap;

  if (gap < 4) {
    for (size_t j = 0; j < gap; ++j) {
      std::uint64_t u = GuardLazy(*x, two_times_modulus);
      std::uint64_t v = *y;
      std::uint64_t sum =
          GuardLazy(AddLazy(u, v, two_times_modulus), two_times_modulus);
      std::uint64_t diff = SubLazy(u, v, two_times_modulus);
      *x++ = MulUintModLazy(sum, inv_n_scaled, modulus);
      *y++ = MulUintModLazy(diff, scaled_inv_root, modulus);
    }
  } else {
    for (size_t j = 0; j < gap; j += 4) {
      // Unroll 4 iterations
      std::uint64_t u = GuardLazy(*x, two_times_modulus);
      std::uint64_t v = *y;
      std::uint64_t sum =
          GuardLazy(AddLazy(u, v, two_times_modulus), two_times_modulus);
      std::uint64_t diff = SubLazy(u, v, two_times_modulus);
      *x++ = MulUintModLazy(sum, inv_n_scaled, modulus);
      *y++ = MulUintModLazy(diff, scaled_inv_root, modulus);

      u = GuardLazy(*x, two_times_modulus);
      v = *y;
      sum = GuardLazy(AddLazy(u, v, two_times_modulus), two_times_modulus);
      diff = SubLazy(u, v, two_times_modulus);
      *x++ = MulUintModLazy(sum, inv_n_scaled, modulus);
      *y++ = MulUintModLazy(diff, scaled_inv_root, modulus);

      u = GuardLazy(*x, two_times_modulus);
      v = *y;
      sum = GuardLazy(AddLazy(u, v, two_times_modulus), two_times_modulus);
      diff = SubLazy(u, v, two_times_modulus);
      *x++ = MulUintModLazy(sum, inv_n_scaled, modulus);
      *y++ = MulUintModLazy(diff, scaled_inv_root, modulus);

      u = GuardLazy(*x, two_times_modulus);
      v = *y;
      sum = GuardLazy(AddLazy(u, v, two_times_modulus), two_times_modulus);
      diff = SubLazy(u, v, two_times_modulus);
      *x++ = MulUintModLazy(sum, inv_n_scaled, modulus);
      *y++ = MulUintModLazy(diff, scaled_inv_root, modulus);
    }
  }
}

void HarveyNTT::HarveyNttLazy4(std::uint64_t *operand0, std::uint64_t *operand1,
                               std::uint64_t *operand2, std::uint64_t *operand3,
                               const NTTTables &tables) {
  const size_t coeff_count = tables.GetCoeffCount();
  const auto *roots = tables.GetRootPowers().data();
  const std::uint64_t modulus = tables.GetModulus().P();
  const std::uint64_t two_times_modulus = modulus << 1;

  size_t gap = coeff_count >> 1;
  size_t m = 1;

  for (; m < (coeff_count >> 1); m <<= 1) {
    size_t offset = 0;

    for (size_t i = 0; i < m; ++i) {
      const auto &root = *++roots;
      std::uint64_t *x0 = operand0 + offset;
      std::uint64_t *y0 = x0 + gap;
      std::uint64_t *x1 = operand1 + offset;
      std::uint64_t *y1 = x1 + gap;
      std::uint64_t *x2 = operand2 + offset;
      std::uint64_t *y2 = x2 + gap;
      std::uint64_t *x3 = operand3 + offset;
      std::uint64_t *y3 = x3 + gap;

      if (gap < 4) {
        for (size_t j = 0; j < gap; ++j) {
          std::uint64_t u = GuardLazy(*x0, two_times_modulus);
          std::uint64_t v = MulUintModLazy(*y0, root, modulus);
          *x0++ = AddLazy(u, v, two_times_modulus);
          *y0++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x1, two_times_modulus);
          v = MulUintModLazy(*y1, root, modulus);
          *x1++ = AddLazy(u, v, two_times_modulus);
          *y1++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x2, two_times_modulus);
          v = MulUintModLazy(*y2, root, modulus);
          *x2++ = AddLazy(u, v, two_times_modulus);
          *y2++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x3, two_times_modulus);
          v = MulUintModLazy(*y3, root, modulus);
          *x3++ = AddLazy(u, v, two_times_modulus);
          *y3++ = SubLazy(u, v, two_times_modulus);
        }
      } else {
        size_t j = 0;
        for (; j + 3 < gap; j += 4) {
          std::uint64_t u = GuardLazy(*x0, two_times_modulus);
          std::uint64_t v = MulUintModLazy(*y0, root, modulus);
          *x0++ = AddLazy(u, v, two_times_modulus);
          *y0++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x0, two_times_modulus);
          v = MulUintModLazy(*y0, root, modulus);
          *x0++ = AddLazy(u, v, two_times_modulus);
          *y0++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x0, two_times_modulus);
          v = MulUintModLazy(*y0, root, modulus);
          *x0++ = AddLazy(u, v, two_times_modulus);
          *y0++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x0, two_times_modulus);
          v = MulUintModLazy(*y0, root, modulus);
          *x0++ = AddLazy(u, v, two_times_modulus);
          *y0++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x1, two_times_modulus);
          v = MulUintModLazy(*y1, root, modulus);
          *x1++ = AddLazy(u, v, two_times_modulus);
          *y1++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x1, two_times_modulus);
          v = MulUintModLazy(*y1, root, modulus);
          *x1++ = AddLazy(u, v, two_times_modulus);
          *y1++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x1, two_times_modulus);
          v = MulUintModLazy(*y1, root, modulus);
          *x1++ = AddLazy(u, v, two_times_modulus);
          *y1++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x1, two_times_modulus);
          v = MulUintModLazy(*y1, root, modulus);
          *x1++ = AddLazy(u, v, two_times_modulus);
          *y1++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x2, two_times_modulus);
          v = MulUintModLazy(*y2, root, modulus);
          *x2++ = AddLazy(u, v, two_times_modulus);
          *y2++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x2, two_times_modulus);
          v = MulUintModLazy(*y2, root, modulus);
          *x2++ = AddLazy(u, v, two_times_modulus);
          *y2++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x2, two_times_modulus);
          v = MulUintModLazy(*y2, root, modulus);
          *x2++ = AddLazy(u, v, two_times_modulus);
          *y2++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x2, two_times_modulus);
          v = MulUintModLazy(*y2, root, modulus);
          *x2++ = AddLazy(u, v, two_times_modulus);
          *y2++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x3, two_times_modulus);
          v = MulUintModLazy(*y3, root, modulus);
          *x3++ = AddLazy(u, v, two_times_modulus);
          *y3++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x3, two_times_modulus);
          v = MulUintModLazy(*y3, root, modulus);
          *x3++ = AddLazy(u, v, two_times_modulus);
          *y3++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x3, two_times_modulus);
          v = MulUintModLazy(*y3, root, modulus);
          *x3++ = AddLazy(u, v, two_times_modulus);
          *y3++ = SubLazy(u, v, two_times_modulus);
          u = GuardLazy(*x3, two_times_modulus);
          v = MulUintModLazy(*y3, root, modulus);
          *x3++ = AddLazy(u, v, two_times_modulus);
          *y3++ = SubLazy(u, v, two_times_modulus);
        }

        for (; j < gap; ++j) {
          std::uint64_t u = GuardLazy(*x0, two_times_modulus);
          std::uint64_t v = MulUintModLazy(*y0, root, modulus);
          *x0++ = AddLazy(u, v, two_times_modulus);
          *y0++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x1, two_times_modulus);
          v = MulUintModLazy(*y1, root, modulus);
          *x1++ = AddLazy(u, v, two_times_modulus);
          *y1++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x2, two_times_modulus);
          v = MulUintModLazy(*y2, root, modulus);
          *x2++ = AddLazy(u, v, two_times_modulus);
          *y2++ = SubLazy(u, v, two_times_modulus);

          u = GuardLazy(*x3, two_times_modulus);
          v = MulUintModLazy(*y3, root, modulus);
          *x3++ = AddLazy(u, v, two_times_modulus);
          *y3++ = SubLazy(u, v, two_times_modulus);
        }
      }
      offset += gap << 1;
    }
    gap >>= 1;
  }

  std::uint64_t *values0 = operand0;
  std::uint64_t *values1 = operand1;
  std::uint64_t *values2 = operand2;
  std::uint64_t *values3 = operand3;
  for (size_t i = 0; i < m; ++i) {
    const auto &root = *++roots;

    std::uint64_t u = GuardLazy(values0[0], two_times_modulus);
    std::uint64_t v = MulUintModLazy(values0[1], root, modulus);
    values0[0] = AddLazy(u, v, two_times_modulus);
    values0[1] = SubLazy(u, v, two_times_modulus);

    u = GuardLazy(values1[0], two_times_modulus);
    v = MulUintModLazy(values1[1], root, modulus);
    values1[0] = AddLazy(u, v, two_times_modulus);
    values1[1] = SubLazy(u, v, two_times_modulus);

    u = GuardLazy(values2[0], two_times_modulus);
    v = MulUintModLazy(values2[1], root, modulus);
    values2[0] = AddLazy(u, v, two_times_modulus);
    values2[1] = SubLazy(u, v, two_times_modulus);

    u = GuardLazy(values3[0], two_times_modulus);
    v = MulUintModLazy(values3[1], root, modulus);
    values3[0] = AddLazy(u, v, two_times_modulus);
    values3[1] = SubLazy(u, v, two_times_modulus);

    values0 += 2;
    values1 += 2;
    values2 += 2;
    values3 += 2;
  }
}

void HarveyNTT::HarveyNtt4(std::uint64_t *operand0, std::uint64_t *operand1,
                           std::uint64_t *operand2, std::uint64_t *operand3,
                           const NTTTables &tables) {
  const size_t coeff_count = tables.GetCoeffCount();
  const std::uint64_t modulus = tables.GetModulus().P();
  const std::uint64_t two_times_modulus = modulus << 1;

  HarveyNttLazy4(operand0, operand1, operand2, operand3, tables);

  auto reduce_full = [&](std::uint64_t *operand) {
    for (size_t i = 0; i < coeff_count; ++i) {
      std::uint64_t v = operand[i];
      std::uint64_t mask = -static_cast<std::int64_t>(v >= two_times_modulus);
      v -= (two_times_modulus & mask);
      mask = -static_cast<std::int64_t>(v >= modulus);
      operand[i] = v - (modulus & mask);
    }
  };
  reduce_full(operand0);
  reduce_full(operand1);
  reduce_full(operand2);
  reduce_full(operand3);
}

void HarveyNTT::InverseHarveyNttLazy3(std::uint64_t *operand0,
                                      std::uint64_t *operand1,
                                      std::uint64_t *operand2,
                                      const NTTTables &tables) {
  const size_t coeff_count = tables.GetCoeffCount();
  const auto *roots = tables.GetInvRootPowers().data();
  const std::uint64_t modulus = tables.GetModulus().P();
  const std::uint64_t two_times_modulus = modulus << 1;

  size_t gap = 1;
  size_t m = coeff_count >> 1;

  for (; m > 1; m >>= 1) {
    size_t offset = 0;
    if (gap < 4) {
      for (size_t i = 0; i < m; ++i) {
        const auto &inv_root = *++roots;
        std::uint64_t *x0 = operand0 + offset;
        std::uint64_t *y0 = x0 + gap;
        std::uint64_t *x1 = operand1 + offset;
        std::uint64_t *y1 = x1 + gap;
        std::uint64_t *x2 = operand2 + offset;
        std::uint64_t *y2 = x2 + gap;

        for (size_t j = 0; j < gap; ++j) {
          std::uint64_t u = *x0;
          std::uint64_t v = *y0;
          std::uint64_t sum = AddLazy(u, v, two_times_modulus);
          std::uint64_t diff = SubLazy(u, v, two_times_modulus);
          *x0++ = GuardLazy(sum, two_times_modulus);
          *y0++ = MulUintModLazy(diff, inv_root, modulus);

          u = *x1;
          v = *y1;
          sum = AddLazy(u, v, two_times_modulus);
          diff = SubLazy(u, v, two_times_modulus);
          *x1++ = GuardLazy(sum, two_times_modulus);
          *y1++ = MulUintModLazy(diff, inv_root, modulus);

          u = *x2;
          v = *y2;
          sum = AddLazy(u, v, two_times_modulus);
          diff = SubLazy(u, v, two_times_modulus);
          *x2++ = GuardLazy(sum, two_times_modulus);
          *y2++ = MulUintModLazy(diff, inv_root, modulus);
        }
        offset += gap << 1;
      }
    } else {
      for (size_t i = 0; i < m; ++i) {
        const auto &inv_root = *++roots;
        std::uint64_t *x0 = operand0 + offset;
        std::uint64_t *y0 = x0 + gap;
        std::uint64_t *x1 = operand1 + offset;
        std::uint64_t *y1 = x1 + gap;
        std::uint64_t *x2 = operand2 + offset;
        std::uint64_t *y2 = x2 + gap;

        for (size_t j = 0; j < gap; j += 4) {
          for (size_t repeat = 0; repeat < 4; ++repeat) {
            (void)repeat;
            std::uint64_t u = *x0;
            std::uint64_t v = *y0;
            std::uint64_t sum = AddLazy(u, v, two_times_modulus);
            std::uint64_t diff = SubLazy(u, v, two_times_modulus);
            *x0++ = GuardLazy(sum, two_times_modulus);
            *y0++ = MulUintModLazy(diff, inv_root, modulus);

            u = *x1;
            v = *y1;
            sum = AddLazy(u, v, two_times_modulus);
            diff = SubLazy(u, v, two_times_modulus);
            *x1++ = GuardLazy(sum, two_times_modulus);
            *y1++ = MulUintModLazy(diff, inv_root, modulus);

            u = *x2;
            v = *y2;
            sum = AddLazy(u, v, two_times_modulus);
            diff = SubLazy(u, v, two_times_modulus);
            *x2++ = GuardLazy(sum, two_times_modulus);
            *y2++ = MulUintModLazy(diff, inv_root, modulus);
          }
        }
        offset += gap << 1;
      }
    }
    gap <<= 1;
  }

  const auto &inv_n = tables.GetInvDegreeModulo();
  const auto &inv_root = *++roots;
  std::uint64_t temp_product = MulUintMod(inv_root.operand, inv_n, modulus);
  zq::MultiplyUIntModOperand scaled_inv_root;
  scaled_inv_root.set(temp_product, modulus);

  std::uint64_t *x0 = operand0;
  std::uint64_t *y0 = x0 + gap;
  std::uint64_t *x1 = operand1;
  std::uint64_t *y1 = x1 + gap;
  std::uint64_t *x2 = operand2;
  std::uint64_t *y2 = x2 + gap;
  for (size_t j = 0; j < gap; ++j) {
    std::uint64_t u = GuardLazy(*x0, two_times_modulus);
    std::uint64_t v = *y0;
    std::uint64_t sum =
        GuardLazy(AddLazy(u, v, two_times_modulus), two_times_modulus);
    std::uint64_t diff = SubLazy(u, v, two_times_modulus);
    *x0++ = MulUintModLazy(sum, inv_n, modulus);
    *y0++ = MulUintModLazy(diff, scaled_inv_root, modulus);

    u = GuardLazy(*x1, two_times_modulus);
    v = *y1;
    sum = GuardLazy(AddLazy(u, v, two_times_modulus), two_times_modulus);
    diff = SubLazy(u, v, two_times_modulus);
    *x1++ = MulUintModLazy(sum, inv_n, modulus);
    *y1++ = MulUintModLazy(diff, scaled_inv_root, modulus);

    u = GuardLazy(*x2, two_times_modulus);
    v = *y2;
    sum = GuardLazy(AddLazy(u, v, two_times_modulus), two_times_modulus);
    diff = SubLazy(u, v, two_times_modulus);
    *x2++ = MulUintModLazy(sum, inv_n, modulus);
    *y2++ = MulUintModLazy(diff, scaled_inv_root, modulus);
  }
}

void HarveyNTT::InverseHarveyNttLazy2(std::uint64_t *operand0,
                                      std::uint64_t *operand1,
                                      const NTTTables &tables) {
  const size_t coeff_count = tables.GetCoeffCount();
  const auto *roots = tables.GetInvRootPowers().data();
  const std::uint64_t modulus = tables.GetModulus().P();
  const std::uint64_t two_times_modulus = modulus << 1;

  size_t gap = 1;
  size_t m = coeff_count >> 1;

  auto apply_stage = [&](std::uint64_t *x, std::uint64_t *y,
                         const zq::MultiplyUIntModOperand &inv_root) {
    std::uint64_t u = *x;
    std::uint64_t v = *y;
    std::uint64_t sum = AddLazy(u, v, two_times_modulus);
    std::uint64_t diff = SubLazy(u, v, two_times_modulus);
    *x = GuardLazy(sum, two_times_modulus);
    *y = MulUintModLazy(diff, inv_root, modulus);
  };

  for (; m > 1; m >>= 1) {
    size_t offset = 0;
    for (size_t i = 0; i < m; ++i) {
      const auto &inv_root = *++roots;
      std::uint64_t *x0 = operand0 + offset;
      std::uint64_t *y0 = x0 + gap;
      std::uint64_t *x1 = operand1 + offset;
      std::uint64_t *y1 = x1 + gap;

      for (size_t j = 0; j < gap; ++j) {
        apply_stage(x0++, y0++, inv_root);
        apply_stage(x1++, y1++, inv_root);
      }
      offset += gap << 1;
    }
    gap <<= 1;
  }

  const auto &inv_n_scaled = tables.GetInvDegreeModulo();
  const auto &inv_root = *++roots;
  std::uint64_t temp_product =
      MulUintMod(inv_root.operand, inv_n_scaled, modulus);
  zq::MultiplyUIntModOperand scaled_inv_root;
  scaled_inv_root.set(temp_product, modulus);

  auto final_stage = [&](std::uint64_t *x, std::uint64_t *y) {
    std::uint64_t u = GuardLazy(*x, two_times_modulus);
    std::uint64_t v = *y;
    std::uint64_t sum =
        GuardLazy(AddLazy(u, v, two_times_modulus), two_times_modulus);
    std::uint64_t diff = SubLazy(u, v, two_times_modulus);
    *x = MulUintModLazy(sum, inv_n_scaled, modulus);
    *y = MulUintModLazy(diff, scaled_inv_root, modulus);
  };

  std::uint64_t *x0 = operand0;
  std::uint64_t *y0 = x0 + gap;
  std::uint64_t *x1 = operand1;
  std::uint64_t *y1 = x1 + gap;
  for (size_t j = 0; j < gap; ++j) {
    final_stage(x0++, y0++);
    final_stage(x1++, y1++);
  }
}

void HarveyNTT::InverseHarveyNtt2(std::uint64_t *operand0,
                                  std::uint64_t *operand1,
                                  const NTTTables &tables) {
  InverseHarveyNttLazy2(operand0, operand1, tables);

  const size_t coeff_count = tables.GetCoeffCount();
  const std::uint64_t modulus = tables.GetModulus().P();
  auto reduce_full = [&](std::uint64_t *operand) {
    for (size_t i = 0; i < coeff_count; ++i) {
      std::uint64_t v = operand[i];
      std::uint64_t mask = -static_cast<std::int64_t>(v >= modulus);
      operand[i] = v - (modulus & mask);
    }
  };
  reduce_full(operand0);
  reduce_full(operand1);
}

void HarveyNTT::InverseHarveyNtt(std::uint64_t *operand,
                                 const NTTTables &tables) {
  // First do lazy inverse
  InverseHarveyNttLazy(operand, tables);

  // Then reduce all coefficients from [0, 2*modulus) to [0, modulus)
  const std::uint64_t modulus = tables.GetModulus().P();
  const size_t n = tables.GetCoeffCount();
  for (size_t i = 0; i < n; ++i) {
    std::uint64_t v = operand[i];
    operand[i] = (v >= modulus) ? v - modulus : v;
  }
}

inline void HarveyNTT::HarveyButterflyLazy(
    std::uint64_t &u, std::uint64_t &v, const zq::MultiplyUIntModOperand &root,
    std::uint64_t modulus) {
  const std::uint64_t two_times_modulus = modulus << 1;
  u = GuardLazy(u, two_times_modulus);
  std::uint64_t t = MulUintModLazy(v, root, modulus);
  v = SubLazy(u, t, two_times_modulus);
  u = AddLazy(u, t, two_times_modulus);
}

inline void HarveyNTT::HarveyButterfly(std::uint64_t &u, std::uint64_t &v,
                                       const zq::MultiplyUIntModOperand &root,
                                       std::uint64_t modulus) {
  HarveyButterflyLazy(u, v, root, modulus);
  // Reduce both to [0, modulus)
  std::uint64_t mask_u = -static_cast<std::int64_t>(u >= modulus);
  u -= (modulus & mask_u);
  std::uint64_t mask_v = -static_cast<std::int64_t>(v >= modulus);
  v -= (modulus & mask_v);
}

inline void HarveyNTT::InverseHarveyButterflyLazy(
    std::uint64_t &u, std::uint64_t &v,
    const zq::MultiplyUIntModOperand &inv_root, std::uint64_t modulus) {
  const std::uint64_t two_times_modulus = modulus << 1;
  u = GuardLazy(u, two_times_modulus);
  v = GuardLazy(v, two_times_modulus);
  std::uint64_t sum = AddLazy(u, v, two_times_modulus);
  std::uint64_t diff = SubLazy(u, v, two_times_modulus);
  u = GuardLazy(sum, two_times_modulus);
  v = MulUintModLazy(diff, inv_root, modulus);
}

inline void HarveyNTT::InverseHarveyButterfly(
    std::uint64_t &u, std::uint64_t &v,
    const zq::MultiplyUIntModOperand &inv_root, std::uint64_t modulus) {
  InverseHarveyButterflyLazy(u, v, inv_root, modulus);
  // Reduce both to [0, modulus)
  std::uint64_t mask_u = -static_cast<std::int64_t>(u >= modulus);
  u -= (modulus & mask_u);
  std::uint64_t mask_v = -static_cast<std::int64_t>(v >= modulus);
  v -= (modulus & mask_v);
}

}  // namespace ntt
}  // namespace math
}  // namespace bfv
