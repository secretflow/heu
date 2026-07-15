#include "math/ntt_optimized.h"

#include <gtest/gtest.h>

#include <random>
#include <vector>

#include "math/modulus.h"
#include "math/ntt_harvey.h"
#include "math/ntt_tables.h"

using namespace bfv::math::ntt;
using namespace bfv::math::zq;

namespace {

constexpr uint64_t kOptimizedNttTestSeed = 0x4F50544E545431ULL;

}  // namespace

class OptimizedNTTTest : public ::testing::Test {
 protected:
  Modulus GetTestModulus() {
    // Use a prime that supports NTT for size 8: p = 17 (17-1 = 16 = 2*8)
    auto mod_opt = Modulus::New(17);
    EXPECT_TRUE(mod_opt.has_value());
    return std::move(*mod_opt);
  }

  std::vector<std::uint64_t> GenerateRandomPoly(size_t size,
                                                const Modulus &modulus) {
    std::vector<std::uint64_t> poly(size);
    std::mt19937_64 gen(kOptimizedNttTestSeed);
    std::uniform_int_distribution<std::uint64_t> dis(0, modulus.P() - 1);

    for (size_t i = 0; i < size; ++i) {
      poly[i] = dis(gen);
    }
    return poly;
  }
};

TEST_F(OptimizedNTTTest, ForwardInverseConsistency) {
  auto modulus = GetTestModulus();
  auto tables_opt = NTTTables::Create(modulus, 8);
  ASSERT_TRUE(tables_opt.has_value());
  auto tables = std::move(*tables_opt);

  // Generate a random polynomial
  auto original = GenerateRandomPoly(8, modulus);
  auto poly = original;

  // Forward NTT (optimized)
  OptimizedNTT::OptimizedNtt(poly.data(), tables);

  // Inverse NTT (optimized)
  OptimizedNTT::InverseOptimizedNtt(poly.data(), tables);

  // Should recover original polynomial
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(poly[i], original[i]) << "Mismatch at index " << i;
  }
}

TEST_F(OptimizedNTTTest, CompareWithHarveyNTT) {
  auto modulus = GetTestModulus();
  auto tables_opt = NTTTables::Create(modulus, 8);
  ASSERT_TRUE(tables_opt.has_value());
  auto tables = std::move(*tables_opt);

  // Generate a random polynomial
  auto original = GenerateRandomPoly(8, modulus);
  auto poly_optimized = original;
  auto poly_harvey = original;

  // Forward NTT (both variants)
  OptimizedNTT::OptimizedNtt(poly_optimized.data(), tables);
  HarveyNTT::HarveyNtt(poly_harvey.data(), tables);

  // Results should be identical
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(poly_optimized[i], poly_harvey[i])
        << "Forward NTT mismatch at index " << i;
  }

  // Inverse NTT (both variants)
  OptimizedNTT::InverseOptimizedNtt(poly_optimized.data(), tables);
  HarveyNTT::InverseHarveyNtt(poly_harvey.data(), tables);

  // Results should be identical and equal to original
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(poly_optimized[i], poly_harvey[i])
        << "Inverse NTT mismatch at index " << i;
    EXPECT_EQ(poly_optimized[i], original[i])
        << "Recovery mismatch at index " << i;
  }
}

TEST_F(OptimizedNTTTest, CacheOptimizedTables) {
  auto modulus = GetTestModulus();
  auto tables_opt = NTTTables::Create(modulus, 8);
  ASSERT_TRUE(tables_opt.has_value());
  auto tables = std::move(*tables_opt);

  // Create cache-optimized tables
  CacheOptimizedNTTTables opt_tables(tables);

  EXPECT_EQ(opt_tables.GetCoeffCount(), 8);
  EXPECT_EQ(opt_tables.GetModulus().P(), 17);

  // Check that flattened arrays are accessible
  const auto *root_powers = opt_tables.GetRootPowersFlat();
  const auto *root_quotients = opt_tables.GetRootQuotientsFlat();
  const auto *inv_root_powers = opt_tables.GetInvRootPowersFlat();
  const auto *inv_root_quotients = opt_tables.GetInvRootQuotientsFlat();

  EXPECT_NE(root_powers, nullptr);
  EXPECT_NE(root_quotients, nullptr);
  EXPECT_NE(inv_root_powers, nullptr);
  EXPECT_NE(inv_root_quotients, nullptr);
}

TEST_F(OptimizedNTTTest, BitReversalOperations) {
  std::vector<std::uint64_t> src = {0, 1, 2, 3, 4, 5, 6, 7};
  std::vector<std::uint64_t> dst(8);
  std::vector<std::uint64_t> data = src;

  // Test bit-reverse copy
  OptimizedNTT::BitReverseCopyOptimized(src.data(), dst.data(), 8);

  // Expected bit-reversed order for 3 bits: [0,4,2,6,1,5,3,7]
  std::vector<std::uint64_t> expected = {0, 4, 2, 6, 1, 5, 3, 7};
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(dst[i], expected[i])
        << "Bit-reverse copy mismatch at index " << i;
  }

  // Test in-place bit-reversal
  OptimizedNTT::BitReverseInplaceOptimized(data.data(), 8);
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(data[i], expected[i])
        << "In-place bit-reverse mismatch at index " << i;
  }
}

TEST_F(OptimizedNTTTest, MemoryAlignment) {
  // Test alignment utilities
  std::uint64_t aligned_data[8] __attribute__((aligned(32)));
  std::uint64_t stack_data[9];

  EXPECT_TRUE(OptimizedNTT::is_aligned(aligned_data, 32));
  EXPECT_TRUE(OptimizedNTT::is_aligned(stack_data, alignof(std::uint64_t)));
}
