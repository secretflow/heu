#include "math/poly.h"

#include <gtest/gtest.h>

#include <array>
#include <cmath>
#include <memory>
#include <random>
#include <vector>

#include "math/biguint.h"
#include "math/context.h"
#include "math/exceptions.h"
#include "math/representation.h"
#include "math/substitution_exponent.h"
#include "math/test_support.h"

namespace bfv::math::rq {

namespace {

const std::vector<uint64_t> &RingBasisSet() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x706f6c795f72696eULL, 5,
                                                    16, 52);
  return basis;
}

std::vector<uint64_t> BuildWideRingBasis() {
  return ::bfv::math::test::GenerateTaggedResidueBasis(0x706f6c795f776964ULL, 1,
                                                       1 << 18, 30);
}

std::shared_ptr<Context> MakePolyContext(size_t basis_size,
                                         size_t degree = 16) {
  return Context::create(
      std::vector<uint64_t>(RingBasisSet().begin(),
                            RingBasisSet().begin() + basis_size),
      degree);
}

}  // namespace

class PolyTest : public ::testing::Test {
 protected:
  void SetUp() override { rng_.seed(20260314); }

  std::mt19937_64 rng_;
};

/**
 * @brief Test zero polynomial creation.
 */
TEST_F(PolyTest, ZeroRowsStayCleared) {
  for (auto modulus : RingBasisSet()) {
    auto ctx = Context::create({modulus}, 16);

    for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                      Representation::NttShoup}) {
      auto p = Poly::zero(ctx, repr);
      EXPECT_EQ(p.representation(), repr);
      EXPECT_EQ(p.ctx(), ctx);

      const auto &coeffs = p.coefficients();
      for (const auto &modulus_coeffs : coeffs) {
        for (uint64_t coeff : modulus_coeffs) {
          EXPECT_EQ(coeff, 0ULL);
        }
      }
    }
  }

  // Test with multiple moduli
  auto ctx = MakePolyContext(RingBasisSet().size());
  for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                    Representation::NttShoup}) {
    auto p = Poly::zero(ctx, repr);
    EXPECT_EQ(p.representation(), repr);
    EXPECT_EQ(p.ctx(), ctx);

    const auto &coeffs = p.coefficients();
    EXPECT_EQ(coeffs.size(), RingBasisSet().size());
    for (const auto &modulus_coeffs : coeffs) {
      EXPECT_EQ(modulus_coeffs.size(), 16);
      for (uint64_t coeff : modulus_coeffs) {
        EXPECT_EQ(coeff, 0ULL);
      }
    }
  }
}

/**
 * @brief Test random polynomial generation.
 */
TEST_F(PolyTest, RandomRowsRespectBasisBounds) {
  for (auto modulus : RingBasisSet()) {
    auto ctx = Context::create({modulus}, 16);

    for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                      Representation::NttShoup}) {
      auto p = Poly::random(ctx, repr, rng_);
      EXPECT_EQ(p.representation(), repr);
      EXPECT_EQ(p.ctx(), ctx);

      const auto &coeffs = p.coefficients();
      for (const auto &modulus_coeffs : coeffs) {
        for (uint64_t coeff : modulus_coeffs) {
          EXPECT_LT(coeff, modulus);
        }
      }
    }
  }

  // Test with multiple moduli
  auto ctx = MakePolyContext(RingBasisSet().size());
  for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                    Representation::NttShoup}) {
    auto p = Poly::random(ctx, repr, rng_);
    EXPECT_EQ(p.representation(), repr);
    EXPECT_EQ(p.ctx(), ctx);

    const auto &coeffs = p.coefficients();
    EXPECT_EQ(coeffs.size(), RingBasisSet().size());
    for (size_t i = 0; i < coeffs.size(); ++i) {
      for (uint64_t coeff : coeffs[i]) {
        EXPECT_LT(coeff, RingBasisSet()[i]);
      }
    }
  }
}

/**
 * @brief Test deterministic random generation from seed.
 */
TEST_F(PolyTest, SeedReplayKeepsRowsStable) {
  std::array<uint8_t, 32> seed = {0};
  for (size_t i = 0; i < 32; ++i) {
    seed[i] = static_cast<uint8_t>(i);
  }

  for (auto modulus : RingBasisSet()) {
    auto ctx = Context::create({modulus}, 16);

    for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                      Representation::NttShoup}) {
      auto p1 = Poly::random_from_seed(ctx, repr, seed);
      auto p2 = Poly::random_from_seed(ctx, repr, seed);

      EXPECT_EQ(p1, p2);
      EXPECT_EQ(p1.representation(), repr);
      EXPECT_EQ(p1.ctx(), ctx);
    }
  }
}

/**
 * @brief Test polynomial conversion to u64 vector.
 */
TEST_F(PolyTest, FlattenedCoefficientViewFollowsRowOrder) {
  for (auto modulus : RingBasisSet()) {
    auto ctx = Context::create({modulus}, 16);

    auto zero_poly = Poly::zero(ctx, Representation::PowerBasis);
    auto zero_vec = zero_poly.to_u64_vector();
    EXPECT_EQ(zero_vec.size(), 16);
    for (uint64_t val : zero_vec) {
      EXPECT_EQ(val, 0ULL);
    }

    auto p = Poly::random(ctx, Representation::PowerBasis, rng_);
    auto p_vec = p.to_u64_vector();
    EXPECT_EQ(p_vec.size(), 16);

    const auto &coeffs = p.coefficients();
    for (size_t i = 0; i < 16; ++i) {
      EXPECT_EQ(p_vec[i], coeffs[0][i]);
    }
  }

  // Test with multiple moduli - should flatten all moduli
  auto ctx = Context::create(
      std::vector<uint64_t>(RingBasisSet().begin(), RingBasisSet().begin() + 3),
      16);
  auto p = Poly::random(ctx, Representation::PowerBasis, rng_);
  auto p_vec = p.to_u64_vector();
  EXPECT_EQ(p_vec.size(), 3 * 16);

  const auto &coeffs = p.coefficients();
  for (size_t mod_idx = 0; mod_idx < 3; ++mod_idx) {
    for (size_t coeff_idx = 0; coeff_idx < 16; ++coeff_idx) {
      EXPECT_EQ(p_vec[mod_idx * 16 + coeff_idx], coeffs[mod_idx][coeff_idx]);
    }
  }
}

/**
 * @brief Test modulus property.
 */
TEST_F(PolyTest, ContextCompositeMatchesBasisProduct) {
  for (auto modulus : RingBasisSet()) {
    ::bfv::math::rns::BigUint modulus_biguint(modulus);
    auto ctx = Context::create({modulus}, 16);
    EXPECT_EQ(ctx->modulus(), modulus_biguint);
  }

  // Test product of multiple moduli
  ::bfv::math::rns::BigUint modulus_product(1);
  for (auto m : RingBasisSet()) {
    modulus_product *= ::bfv::math::rns::BigUint(m);
  }
  auto ctx = MakePolyContext(RingBasisSet().size());
  EXPECT_EQ(ctx->modulus(), modulus_product);
}

/**
 * @brief Test variable time computations flag.
 */
TEST_F(PolyTest, VariableTimeFlagTracksOperators) {
  for (auto modulus : RingBasisSet()) {
    auto ctx = Context::create({modulus}, 16);
    auto p = Poly::random(ctx, Representation::PowerBasis, rng_);

    p.enable_relaxed_arithmetic();
    auto q = p;

    p.disable_relaxed_arithmetic();
  }

  auto ctx = MakePolyContext(RingBasisSet().size());
  auto p = Poly::random(ctx, Representation::Ntt, rng_);
  p.enable_relaxed_arithmetic();
  auto q = Poly::random(ctx, Representation::Ntt, rng_);

  q *= p;
  q.disable_relaxed_arithmetic();
  q += p;
  q.disable_relaxed_arithmetic();
  q -= p;
  auto r = -p;
  (void)r;
}

/**
 * @brief Test representation changes.
 */
TEST_F(PolyTest, RepresentationRoundTripAcrossStorageTags) {
  auto ctx = MakePolyContext(RingBasisSet().size());

  auto p = Poly::random(ctx, Representation::PowerBasis, rng_);
  EXPECT_EQ(p.representation(), Representation::PowerBasis);

  p.change_representation(Representation::PowerBasis);
  EXPECT_EQ(p.representation(), Representation::PowerBasis);
  auto q = p;

  p.change_representation(Representation::Ntt);
  EXPECT_EQ(p.representation(), Representation::Ntt);
  EXPECT_NE(p.coefficients(), q.coefficients());
  auto q_ntt = p;

  p.change_representation(Representation::NttShoup);
  EXPECT_EQ(p.representation(), Representation::NttShoup);
  EXPECT_NE(p.coefficients(), q.coefficients());
  auto q_ntt_shoup = p;

  p.change_representation(Representation::PowerBasis);
  EXPECT_EQ(p, q);

  p.change_representation(Representation::NttShoup);
  EXPECT_EQ(p, q_ntt_shoup);

  p.change_representation(Representation::Ntt);
  EXPECT_EQ(p, q_ntt);

  p.change_representation(Representation::PowerBasis);
  EXPECT_EQ(p, q);
}

/**
 * @brief Test representation override.
 */
TEST_F(PolyTest, RepresentationTagOverrideKeepsRawRows) {
  auto ctx = MakePolyContext(RingBasisSet().size());

  auto p = Poly::random(ctx, Representation::PowerBasis, rng_);
  EXPECT_EQ(p.representation(), Representation::PowerBasis);
  auto q = p;

  p.override_representation(Representation::Ntt);
  EXPECT_EQ(p.representation(), Representation::Ntt);
  EXPECT_EQ(p.coefficients(), q.coefficients());

  p.override_representation(Representation::NttShoup);
  EXPECT_EQ(p.representation(), Representation::NttShoup);
  EXPECT_EQ(p.coefficients(), q.coefficients());

  p.override_representation(Representation::PowerBasis);
  EXPECT_EQ(p, q);

  p.override_representation(Representation::NttShoup);
  p.override_representation(Representation::Ntt);
}

/**
 * @brief Test small polynomial generation.
 */
TEST_F(PolyTest, SmallNoiseSamplingStaysBounded) {
  for (auto modulus : RingBasisSet()) {
    auto ctx = Context::create({modulus}, 16);

    EXPECT_THROW(Poly::small(ctx, Representation::PowerBasis, 0, rng_),
                 DefaultException);
    EXPECT_THROW(Poly::small(ctx, Representation::PowerBasis, 17, rng_),
                 DefaultException);

    for (size_t variance = 1; variance <= 16; ++variance) {
      auto p = Poly::small(ctx, Representation::PowerBasis, variance, rng_);
      auto coeffs_vec = p.to_u64_vector();
      for (uint64_t coeff : coeffs_vec) {
        int64_t signed_coeff;
        if (coeff <= modulus / 2) {
          signed_coeff = static_cast<int64_t>(coeff);
        } else {
          signed_coeff = static_cast<int64_t>(coeff - modulus);
        }

        EXPECT_LE(std::abs(signed_coeff), static_cast<int64_t>(2 * variance));
      }
    }
  }

  auto ctx = Context::create(BuildWideRingBasis(), 1 << 18);
  auto p = Poly::small(ctx, Representation::PowerBasis, 16, rng_);
  auto coeffs_vec = p.to_u64_vector();

  // Convert to signed and check maximum absolute value
  int64_t max_abs = 0;
  double sum_squares = 0.0;
  for (uint64_t coeff : coeffs_vec) {
    int64_t signed_coeff;
    if (coeff <= ctx->residue_basis()[0] / 2) {
      signed_coeff = static_cast<int64_t>(coeff);
    } else {
      signed_coeff = static_cast<int64_t>(coeff - ctx->residue_basis()[0]);
    }

    max_abs = std::max(max_abs, std::abs(signed_coeff));
    sum_squares += static_cast<double>(signed_coeff * signed_coeff);
  }

  EXPECT_LE(max_abs, 32);
  double variance = sum_squares / coeffs_vec.size();
  EXPECT_NEAR(variance, 16.0, 2.0);
}

/**
 * @brief Test substitution operation.
 */
TEST_F(PolyTest, AutomorphismPermutation) {
  constexpr size_t kDegree = 16;
  constexpr size_t kForwardAutomorphism = 5;
  constexpr size_t kInverseAutomorphism = 13;
  auto expected_after_substitution = [&](const std::vector<uint64_t> &coeffs,
                                         uint64_t modulus_value) {
    std::vector<uint64_t> expected(kDegree, 0);
    for (size_t coeff_index = 0; coeff_index < kDegree; ++coeff_index) {
      const size_t remapped_index =
          (kForwardAutomorphism * coeff_index) % kDegree;
      const bool wraps_negacyclic =
          ((kForwardAutomorphism * coeff_index) / kDegree) & 1;
      if (wraps_negacyclic && coeffs[coeff_index] > 0) {
        expected[remapped_index] =
            (expected[remapped_index] + modulus_value - coeffs[coeff_index]) %
            modulus_value;
      } else {
        expected[remapped_index] =
            (expected[remapped_index] + coeffs[coeff_index]) % modulus_value;
      }
    }
    return expected;
  };

  for (auto modulus : RingBasisSet()) {
    auto ctx = Context::create({modulus}, kDegree);
    auto p = Poly::random(ctx, Representation::PowerBasis, rng_);
    auto p_ntt = p;
    p_ntt.change_representation(Representation::Ntt);
    auto p_ntt_shoup = p;
    p_ntt_shoup.change_representation(Representation::NttShoup);
    auto p_coeffs = p.to_u64_vector();

    // Substitution by multiples of 2*degree or even numbers should fail
    EXPECT_THROW(SubstitutionExponent::create(ctx, 0), DefaultException);
    EXPECT_THROW(SubstitutionExponent::create(ctx, 2), DefaultException);
    EXPECT_THROW(SubstitutionExponent::create(ctx, kDegree), DefaultException);

    // Substitution by 1 should leave polynomials unchanged
    auto sub1 = SubstitutionExponent::create(ctx, 1);
    EXPECT_EQ(p, p.apply_automorphism(*sub1));
    EXPECT_EQ(p_ntt, p_ntt.apply_automorphism(*sub1));
    EXPECT_EQ(p_ntt_shoup, p_ntt_shoup.apply_automorphism(*sub1));

    auto forward_substitution =
        SubstitutionExponent::create(ctx, kForwardAutomorphism);
    auto q = p.apply_automorphism(*forward_substitution);
    auto expected = expected_after_substitution(p_coeffs, modulus);

    auto q_vec = q.to_u64_vector();
    EXPECT_EQ(q_vec, expected);

    auto q_ntt = p_ntt.apply_automorphism(*forward_substitution);
    q.change_representation(Representation::Ntt);
    EXPECT_EQ(q, q_ntt);

    auto q_ntt_shoup = p_ntt_shoup.apply_automorphism(*forward_substitution);
    q.change_representation(Representation::NttShoup);
    EXPECT_EQ(q, q_ntt_shoup);

    auto inverse_substitution =
        SubstitutionExponent::create(ctx, kInverseAutomorphism);
    EXPECT_EQ(p, p.apply_automorphism(*forward_substitution)
                     .apply_automorphism(*inverse_substitution));
    EXPECT_EQ(p_ntt, p_ntt.apply_automorphism(*forward_substitution)
                         .apply_automorphism(*inverse_substitution));
    EXPECT_EQ(p_ntt_shoup, p_ntt_shoup.apply_automorphism(*forward_substitution)
                               .apply_automorphism(*inverse_substitution));
  }

  // Test with multiple moduli
  auto ctx = Context::create(RingBasisSet(), 16);
  auto p = Poly::random(ctx, Representation::PowerBasis, rng_);
  auto p_ntt = p;
  p_ntt.change_representation(Representation::Ntt);
  auto p_ntt_shoup = p;
  p_ntt_shoup.change_representation(Representation::NttShoup);

  auto forward_substitution =
      SubstitutionExponent::create(ctx, kForwardAutomorphism);
  auto inverse_substitution =
      SubstitutionExponent::create(ctx, kInverseAutomorphism);

  EXPECT_EQ(p, p.apply_automorphism(*forward_substitution)
                   .apply_automorphism(*inverse_substitution));
  EXPECT_EQ(p_ntt, p_ntt.apply_automorphism(*forward_substitution)
                       .apply_automorphism(*inverse_substitution));
  EXPECT_EQ(p_ntt_shoup, p_ntt_shoup.apply_automorphism(*forward_substitution)
                             .apply_automorphism(*inverse_substitution));
}

/**
 * @brief Test modulus switch down next.
 */
TEST_F(PolyTest, DropLastModulusWithRounding) {
  const int ntests = 100;
  auto ctx = Context::create(RingBasisSet(), 16);

  for (int test = 0; test < ntests; ++test) {
    // Test error for incorrect representation
    auto p_ntt = Poly::random(ctx, Representation::Ntt, rng_);
    EXPECT_THROW(p_ntt.drop_last_residue(), DefaultException);

    // Test successful modulus switch
    auto p = Poly::random(ctx, Representation::PowerBasis, rng_);
    auto reference = p.to_biguint_vector();
    auto current_ctx = ctx;
    EXPECT_EQ(p.ctx(), current_ctx);

    while (current_ctx->lower_level()) {
      auto denominator = current_ctx->modulus();
      current_ctx =
          std::const_pointer_cast<Context>(current_ctx->lower_level());
      auto numerator = current_ctx->modulus();

      p.drop_last_residue();
      EXPECT_EQ(p.ctx(), current_ctx);

      auto p_biguint = p.to_biguint_vector();

      // Verify the modulus switch formula: ((b * numerator) + (denominator >>
      // 1)) / denominator
      for (size_t i = 0; i < reference.size(); ++i) {
        auto expected =
            ((reference[i] * numerator) + (denominator >> 1)) / denominator;
        expected = expected % current_ctx->modulus();
        EXPECT_EQ(p_biguint[i], expected);
      }

      reference = p_biguint;
    }
  }
}

/**
 * @brief Test modulus switch down to specific context.
 */
TEST_F(PolyTest, DropToRequestedLevel) {
  const int ntests = 100;
  auto ctx1 = Context::create(RingBasisSet(), 16);
  // Get the child context from ctx1 instead of creating a new one
  auto ctx2 = ctx1->context_at_level(1);

  for (int test = 0; test < ntests; ++test) {
    auto p = Poly::random(ctx1, Representation::PowerBasis, rng_);
    auto reference = p.to_biguint_vector();

    p.drop_to_context(ctx2);

    EXPECT_EQ(p.ctx(), ctx2);

    auto p_biguint = p.to_biguint_vector();
    for (size_t i = 0; i < reference.size(); ++i) {
      auto expected =
          ((reference[i] * ctx2->modulus()) + (ctx1->modulus() >> 1)) /
          ctx1->modulus();
      EXPECT_EQ(p_biguint[i], expected);
    }
  }
}

/**
 * @brief Test multiply by inverse power of x.
 */
TEST_F(PolyTest, NegacyclicShiftByInversePower) {
  auto ctx = Context::create(RingBasisSet(), 16);

  // Test error for incorrect representation
  auto p_ntt = Poly::random(ctx, Representation::Ntt, rng_);
  EXPECT_THROW(p_ntt.multiply_inverse_power_of_x(1), DefaultException);

  auto p = Poly::random(ctx, Representation::PowerBasis, rng_);
  auto q = p;

  // Multiply by x^(-0) should leave polynomial unchanged
  p.multiply_inverse_power_of_x(0);
  EXPECT_EQ(p, q);

  // Multiply by x^(-1) should change polynomial
  p.multiply_inverse_power_of_x(1);
  EXPECT_NE(p, q);

  // Multiply by x^(-(2*degree-1)) should restore original
  p.multiply_inverse_power_of_x(2 * ctx->degree() - 1);
  EXPECT_EQ(p, q);

  // Multiply by x^(-degree) should negate coefficients
  p.multiply_inverse_power_of_x(ctx->degree());
  auto p_biguint = p.to_biguint_vector();
  auto q_biguint = q.to_biguint_vector();

  for (size_t i = 0; i < p_biguint.size(); ++i) {
    EXPECT_EQ(p_biguint[i], ctx->modulus() - q_biguint[i]);
  }
}

}  // namespace bfv::math::rq
