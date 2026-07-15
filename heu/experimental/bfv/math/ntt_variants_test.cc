#include <gtest/gtest.h>

#include <random>
#include <vector>

#include "math/modulus.h"
#include "math/ntt.h"

using namespace bfv::math::ntt;
using namespace bfv::math::zq;

namespace {

constexpr uint64_t kNttTestSeed = 0x4E54545F56415231ULL;

}  // namespace

class NTTVariantsTest : public ::testing::Test {
 protected:
  NttOperator GetNttOperator() {
    // Use a prime that supports NTT for size 8: p = 17 (17-1 = 16 = 2*8)
    auto mod_opt = Modulus::New(17);
    EXPECT_TRUE(mod_opt.has_value());

    auto ntt_opt = NttOperator::New(*mod_opt, 8);
    EXPECT_TRUE(ntt_opt.has_value());
    return std::move(*ntt_opt);
  }

  std::vector<uint64_t> GetTestPoly() {
    auto mod_opt = Modulus::New(17);
    EXPECT_TRUE(mod_opt.has_value());

    // Use a fixed seed so the regression cases are reproducible.
    std::mt19937_64 gen(kNttTestSeed);
    std::uniform_int_distribution<uint64_t> dis(0, mod_opt->P() - 1);

    std::vector<uint64_t> test_poly(8);
    for (size_t i = 0; i < 8; ++i) {
      test_poly[i] = dis(gen);
    }
    return test_poly;
  }
};

TEST_F(NTTVariantsTest, OriginalNTTConsistency) {
  auto ntt_op = GetNttOperator();
  auto test_poly = GetTestPoly();
  auto poly = test_poly;

  // Forward and backward using original implementation
  auto forward_result = ntt_op.Forward(poly);
  auto recovered = ntt_op.Backward(forward_result);

  // Should recover original polynomial
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(recovered[i], test_poly[i])
        << "Original NTT mismatch at index " << i;
  }
}

TEST_F(NTTVariantsTest, HarveyNTTConsistency) {
  auto ntt_op = GetNttOperator();
  auto test_poly = GetTestPoly();
  auto poly = test_poly;

  // Forward and backward using Harvey implementation
  auto forward_result = ntt_op.ForwardHarvey(poly);
  auto recovered = ntt_op.BackwardHarvey(forward_result);

  // Should recover original polynomial
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(recovered[i], test_poly[i])
        << "Harvey NTT mismatch at index " << i;
  }
}

TEST_F(NTTVariantsTest, HarveyLazyNTTConsistency) {
  auto ntt_op = GetNttOperator();
  auto test_poly = GetTestPoly();
  auto poly = test_poly;

  // Forward and backward using Harvey lazy implementation.
  auto forward_result = ntt_op.ForwardHarveyLazy(poly);

  // Lazy forward output can stay in [0, 4q); normalize back to the inverse
  // precondition range [0, 2q) before calling the lazy inverse.
  constexpr uint64_t modulus = 17;
  const uint64_t two_times_modulus = modulus << 1;
  for (auto &coeff : forward_result) {
    if (coeff >= two_times_modulus) {
      coeff -= two_times_modulus;
    }
  }

  auto recovered = ntt_op.BackwardHarveyLazy(forward_result);

  // Should recover original polynomial after reduction.
  for (size_t i = 0; i < 8; ++i) {
    while (recovered[i] >= modulus) {
      recovered[i] -= modulus;
    }
    EXPECT_EQ(recovered[i], test_poly[i])
        << "Harvey lazy NTT mismatch at index " << i;
  }
}

TEST_F(NTTVariantsTest, OptimizedNTTConsistency) {
  auto ntt_op = GetNttOperator();
  auto test_poly = GetTestPoly();
  auto poly = test_poly;

  // Forward and backward using optimized implementation
  auto forward_result = ntt_op.ForwardOptimized(poly);
  auto recovered = ntt_op.BackwardOptimized(forward_result);

  // Should recover original polynomial
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(recovered[i], test_poly[i])
        << "Optimized NTT mismatch at index " << i;
  }
}

TEST_F(NTTVariantsTest, AllVariantsProduceSameForwardResult) {
  auto ntt_op = GetNttOperator();
  auto test_poly = GetTestPoly();

  // All non-lazy forward variants should produce the same result
  auto original_result = ntt_op.Forward(test_poly);
  auto harvey_result = ntt_op.ForwardHarvey(test_poly);
  auto optimized_result = ntt_op.ForwardOptimized(test_poly);

  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(harvey_result[i], original_result[i])
        << "Harvey vs Original forward mismatch at index " << i;
    EXPECT_EQ(optimized_result[i], original_result[i])
        << "Optimized vs Original forward mismatch at index " << i;
  }
}

TEST_F(NTTVariantsTest, AllVariantsProduceSameBackwardResult) {
  auto ntt_op = GetNttOperator();
  auto test_poly = GetTestPoly();

  // Transform with one variant, then use all variants for inverse
  auto forward_result = ntt_op.ForwardHarvey(test_poly);

  auto original_recovered = ntt_op.Backward(forward_result);
  auto harvey_recovered = ntt_op.BackwardHarvey(forward_result);
  auto optimized_recovered = ntt_op.BackwardOptimized(forward_result);

  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(harvey_recovered[i], original_recovered[i])
        << "Harvey vs Original backward mismatch at index " << i;
    EXPECT_EQ(optimized_recovered[i], original_recovered[i])
        << "Optimized vs Original backward mismatch at index " << i;
    EXPECT_EQ(original_recovered[i], test_poly[i])
        << "Recovery mismatch at index " << i;
  }
}

TEST_F(NTTVariantsTest, LazyVsNonLazyEquivalence) {
  auto ntt_op = GetNttOperator();
  auto test_poly = GetTestPoly();

  // Lazy variants should produce equivalent results after proper reduction
  auto harvey_result = ntt_op.ForwardHarvey(test_poly);
  auto harvey_lazy_result = ntt_op.ForwardHarveyLazy(test_poly);

  // Reduce lazy results to [0, modulus) for comparison
  for (size_t i = 0; i < 8; ++i) {
    while (harvey_lazy_result[i] >= 17) {
      harvey_lazy_result[i] -= 17;
    }
  }

  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(harvey_lazy_result[i], harvey_result[i])
        << "Lazy vs non-lazy forward mismatch at index " << i;
  }
}

TEST_F(NTTVariantsTest, MixedVariantCompatibility) {
  auto ntt_op = GetNttOperator();
  auto test_poly = GetTestPoly();

  // Test that different variants can be mixed (forward with one, backward with
  // another)
  auto harvey_forward = ntt_op.ForwardHarvey(test_poly);
  auto optimized_backward = ntt_op.BackwardOptimized(harvey_forward);

  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(optimized_backward[i], test_poly[i])
        << "Mixed variant mismatch at index " << i;
  }

  auto optimized_forward = ntt_op.ForwardOptimized(test_poly);
  auto harvey_backward = ntt_op.BackwardHarvey(optimized_forward);

  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(harvey_backward[i], test_poly[i])
        << "Mixed variant mismatch (reverse) at index " << i;
  }
}
