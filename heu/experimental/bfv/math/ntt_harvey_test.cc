#include "math/ntt_harvey.h"

#include <gtest/gtest.h>

#include <random>
#include <vector>

#include "math/modulus.h"
#include "math/ntt_tables.h"

using namespace bfv::math::ntt;
using namespace bfv::math::zq;

namespace {

constexpr uint64_t kHarveyNttTestSeed = 0x4841525645594E31ULL;

}  // namespace

class HarveyNTTTest : public ::testing::Test {
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
    std::mt19937_64 gen(kHarveyNttTestSeed);
    std::uniform_int_distribution<std::uint64_t> dis(0, modulus.P() - 1);

    for (size_t i = 0; i < size; ++i) {
      poly[i] = dis(gen);
    }
    return poly;
  }
};

TEST_F(HarveyNTTTest, ForwardInverseConsistency) {
  auto modulus = GetTestModulus();
  auto tables_opt = NTTTables::Create(modulus, 8);
  ASSERT_TRUE(tables_opt.has_value());
  auto tables = std::move(*tables_opt);

  // Generate a random polynomial
  auto original = GenerateRandomPoly(8, modulus);
  auto poly = original;

  // Forward NTT
  HarveyNTT::HarveyNtt(poly.data(), tables);

  // Inverse NTT
  HarveyNTT::InverseHarveyNtt(poly.data(), tables);

  // Should recover original polynomial
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(poly[i], original[i]) << "Mismatch at index " << i;
  }
}

TEST_F(HarveyNTTTest, LazyForwardInverseConsistency) {
  auto modulus = GetTestModulus();
  auto tables_opt = NTTTables::Create(modulus, 8);
  ASSERT_TRUE(tables_opt.has_value());
  auto tables = std::move(*tables_opt);

  // Generate a random polynomial
  auto original = GenerateRandomPoly(8, modulus);
  auto poly = original;

  // Forward NTT (lazy)
  HarveyNTT::HarveyNttLazy(poly.data(), tables);

  // Lazy forward output stays in [0, 4q); normalize back to the inverse
  // precondition range [0, 2q) before applying the lazy inverse.
  const uint64_t two_times_modulus = modulus.P() << 1;
  for (size_t i = 0; i < 8; ++i) {
    poly[i] =
        (poly[i] >= two_times_modulus) ? poly[i] - two_times_modulus : poly[i];
  }

  // Inverse NTT (lazy)
  HarveyNTT::InverseHarveyNttLazy(poly.data(), tables);

  // Reduce results to [0, modulus) for comparison
  for (size_t i = 0; i < 8; ++i) {
    poly[i] = Arithmetic<std::uint64_t>::GuardFull(poly[i], modulus.P());
  }

  // Should recover original polynomial
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(poly[i], original[i]) << "Mismatch at index " << i;
  }
}

TEST_F(HarveyNTTTest, LazyVsNonLazyEquivalence) {
  auto modulus = GetTestModulus();
  auto tables_opt = NTTTables::Create(modulus, 8);
  ASSERT_TRUE(tables_opt.has_value());
  auto tables = std::move(*tables_opt);

  // Generate a random polynomial
  auto original = GenerateRandomPoly(8, modulus);
  auto poly_lazy = original;
  auto poly_normal = original;

  // Forward NTT (both variants)
  HarveyNTT::HarveyNttLazy(poly_lazy.data(), tables);
  HarveyNTT::HarveyNtt(poly_normal.data(), tables);

  // Reduce lazy results to [0, modulus) for comparison
  for (size_t i = 0; i < 8; ++i) {
    poly_lazy[i] =
        Arithmetic<std::uint64_t>::GuardFull(poly_lazy[i], modulus.P());
  }

  // Results should be equivalent after reduction
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(poly_lazy[i], poly_normal[i])
        << "Forward NTT mismatch at index " << i;
  }
}

TEST_F(HarveyNTTTest, ArithmeticGuardFunction) {
  std::uint64_t modulus = 17;

  // Test guard function
  EXPECT_EQ(Arithmetic<std::uint64_t>::Guard(5, modulus), 5);
  EXPECT_EQ(Arithmetic<std::uint64_t>::Guard(16, modulus), 16);
  EXPECT_EQ(Arithmetic<std::uint64_t>::Guard(17, modulus), 0);
  EXPECT_EQ(Arithmetic<std::uint64_t>::Guard(18, modulus), 1);
  EXPECT_EQ(Arithmetic<std::uint64_t>::Guard(33, modulus), 16);
}

TEST_F(HarveyNTTTest, ArithmeticLazyOperations) {
  std::uint64_t modulus = 17;

  // Test lazy addition
  EXPECT_EQ(Arithmetic<std::uint64_t>::AddLazy(10, 5, modulus), 15);
  EXPECT_EQ(Arithmetic<std::uint64_t>::AddLazy(10, 20, modulus), 30);
  EXPECT_EQ(Arithmetic<std::uint64_t>::AddLazy(20, 20, modulus),
            6);  // 40 - 34 = 6

  // Test lazy subtraction
  EXPECT_EQ(Arithmetic<std::uint64_t>::SubLazy(10, 5, modulus), 5);
  EXPECT_EQ(Arithmetic<std::uint64_t>::SubLazy(5, 10, modulus),
            29);  // 5 + 34 - 10 = 29
}
