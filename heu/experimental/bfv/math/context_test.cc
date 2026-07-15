#include "math/context.h"

#include <gtest/gtest.h>

#include <array>
#include <memory>
#include <vector>

#include "math/biguint.h"
#include "math/exceptions.h"
#include "math/modulus.h"
#include "math/test_support.h"

namespace bfv::math::rq {

namespace {

const std::vector<uint64_t> &ContextBasisSet() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x6374785f6c61796fULL, 5,
                                                    16, 52);
  return basis;
}

std::shared_ptr<Context> MakeRingContext(size_t basis_size,
                                         size_t degree = 16) {
  return Context::create(
      std::vector<uint64_t>(ContextBasisSet().begin(),
                            ContextBasisSet().begin() + basis_size),
      degree);
}

void ExpectBasisPrefix(const std::shared_ptr<const Context> &ctx,
                       size_t basis_size) {
  ASSERT_EQ(ctx->residue_basis().size(), basis_size);
  for (size_t i = 0; i < basis_size; ++i) {
    EXPECT_EQ(ctx->residue_basis()[i], ContextBasisSet()[i]);
  }
}

}  // namespace

class ContextTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Setup any common test data
  }
};

/**
 * @brief Single-prime ring layout should build without a lower-level chain.
 */
TEST_F(ContextTest, SinglePrimeLayoutHasNoLowerChain) {
  for (auto modulus : ContextBasisSet()) {
    auto ctx = Context::create({modulus}, 16);

    EXPECT_EQ(ctx->degree(), 16);
    EXPECT_EQ(ctx->residue_basis().size(), 1);
    EXPECT_EQ(ctx->residue_basis()[0], modulus);
    EXPECT_EQ(ctx->modulus(), ::bfv::math::rns::BigUint(modulus));

    const auto &mod_ops = ctx->residue_operators();
    EXPECT_EQ(mod_ops.size(), 1);
    EXPECT_EQ(mod_ops[0].P(), modulus);

    EXPECT_EQ(ctx->lower_level(), nullptr);
  }
}

/**
 * @brief Multi-prime ring layout should preserve the full residue basis.
 */
TEST_F(ContextTest, MultiPrimeLayoutKeepsFullBasisProduct) {
  auto ctx = MakeRingContext(ContextBasisSet().size());

  EXPECT_EQ(ctx->degree(), 16);
  ExpectBasisPrefix(ctx, ContextBasisSet().size());

  // Check product of moduli
  ::bfv::math::rns::BigUint expected_modulus(1);
  for (auto m : ContextBasisSet()) {
    expected_modulus *= ::bfv::math::rns::BigUint(m);
  }
  EXPECT_EQ(ctx->modulus(), expected_modulus);

  // Check moduli operators
  const auto &mod_ops = ctx->residue_operators();
  EXPECT_EQ(mod_ops.size(), ContextBasisSet().size());
  for (size_t i = 0; i < ContextBasisSet().size(); ++i) {
    EXPECT_EQ(mod_ops[i].P(), ContextBasisSet()[i]);
  }

  // Multiple moduli context should have next context
  EXPECT_NE(ctx->lower_level(), nullptr);
}

/**
 * @brief Lower-level contexts should form a tail-dropping chain.
 */
TEST_F(ContextTest, TailDropChainTracksBasisPrefixes) {
  auto ctx = MakeRingContext(ContextBasisSet().size());

  // Walk through the context chain
  std::shared_ptr<const Context> current_ctx = ctx;
  size_t expected_size = ContextBasisSet().size();

  while (current_ctx) {
    EXPECT_EQ(current_ctx->residue_basis().size(), expected_size);
    EXPECT_EQ(current_ctx->degree(), 16);
    ExpectBasisPrefix(current_ctx, expected_size);

    // Check modulus product
    ::bfv::math::rns::BigUint expected_modulus(1);
    for (size_t i = 0; i < expected_size; ++i) {
      expected_modulus *= ::bfv::math::rns::BigUint(ContextBasisSet()[i]);
    }
    EXPECT_EQ(current_ctx->modulus(), expected_modulus);

    current_ctx = current_ctx->lower_level();
    if (expected_size > 1) {
      expected_size--;
    } else {
      // Should be null for single modulus context
      EXPECT_EQ(current_ctx, nullptr);
    }
  }
}

/**
 * @brief Selecting a lower ring level should expose the expected residue
 * prefix.
 */
TEST_F(ContextTest, SelectingLowerLevelKeepsExpectedPrefix) {
  auto ctx = MakeRingContext(ContextBasisSet().size());

  // Level 0 should preserve the full ring layout.
  auto ctx_level_0 = ctx->context_at_level(0);
  EXPECT_EQ(ctx_level_0->residue_basis().size(), ContextBasisSet().size());
  EXPECT_EQ(ctx_level_0->modulus(), ctx->modulus());

  // Lower levels should progressively drop tail basis elements.
  for (size_t level = 1; level < ContextBasisSet().size(); ++level) {
    auto ctx_at_level = ctx->context_at_level(level);
    size_t expected_size = ContextBasisSet().size() - level;

    EXPECT_EQ(ctx_at_level->residue_basis().size(), expected_size);
    EXPECT_EQ(ctx_at_level->degree(), 16);
    ExpectBasisPrefix(ctx_at_level, expected_size);
  }

  // Out-of-range ring levels must fail.
  EXPECT_THROW(ctx->context_at_level(ContextBasisSet().size()),
               DefaultException);
  EXPECT_THROW(ctx->context_at_level(ContextBasisSet().size() + 1),
               DefaultException);
}

/**
 * @brief Count how many tail drops separate two ring levels.
 */
TEST_F(ContextTest, DropDistanceMatchesChainDepth) {
  auto ctx = MakeRingContext(ContextBasisSet().size());

  // Test iterations to self
  EXPECT_EQ(ctx->level_drop_distance(ctx), 0);

  // Test iterations to next contexts
  std::shared_ptr<const Context> current_ctx = ctx;
  size_t expected_iterations = 0;

  while (current_ctx->lower_level()) {
    auto next_ctx = current_ctx->lower_level();
    expected_iterations++;

    EXPECT_EQ(ctx->level_drop_distance(next_ctx), expected_iterations);

    current_ctx = next_ctx;
  }

  // Test with incompatible context (different degree)
  auto incompatible_ctx = Context::create(
      ::bfv::math::test::BuildSingleResidueFixture(32, 0x64726f7032ULL), 32);
  EXPECT_THROW(ctx->level_drop_distance(incompatible_ctx),
               InvalidContextException);

  // Test with context that's not in the chain
  auto unrelated_ctx = Context::create({ContextBasisSet()[1]}, 16);
  EXPECT_THROW(ctx->level_drop_distance(unrelated_ctx),
               InvalidContextException);
}

/**
 * @brief Test degree validation.
 */
TEST_F(ContextTest, DegreeValidationRejectsUnsupportedShapes) {
  // Test valid degrees (powers of 2 >= 8) with a larger modulus that supports
  // NTT
  for (size_t degree : {8, 16, 32, 64}) {
    auto ctx = Context::create(
        ::bfv::math::test::BuildSingleResidueFixture(degree, 0x6465677265ULL),
        degree);
    EXPECT_EQ(ctx->degree(), degree);
  }

  // Test invalid degrees (less than 8)
  for (size_t degree : {1, 2, 3, 4, 5, 6, 7}) {
    EXPECT_THROW(Context::create({ContextBasisSet()[0]}, degree),
                 DefaultException);
  }

  // Test invalid degrees (not powers of 2, but >= 8)
  for (size_t degree : {9, 15, 17, 31, 33}) {
    EXPECT_THROW(Context::create({ContextBasisSet()[0]}, degree),
                 DefaultException);
  }

  // Test very large degree
  EXPECT_THROW(Context::create({ContextBasisSet()[0]}, 1ULL << 32),
               DefaultException);
}

/**
 * @brief Test modulus validation.
 */
TEST_F(ContextTest, BasisValidationRejectsUnsupportedResidues) {
  // Test with empty moduli vector
  EXPECT_THROW(Context::create({}, 16), std::runtime_error);

  // Test with invalid moduli (not prime or not supporting NTT)
  std::vector<uint64_t> invalid_moduli = {4, 6, 8, 9, 10, 12, 15, 16};
  for (auto modulus : invalid_moduli) {
    EXPECT_THROW(Context::create({modulus}, 16), DefaultException);
  }

  // Test with modulus = 1 (invalid)
  EXPECT_THROW(Context::create({1}, 16), std::runtime_error);

  // Test with modulus = 0 (invalid)
  EXPECT_THROW(Context::create({0}, 16), std::runtime_error);
}

/**
 * @brief Test internal data structures.
 */
TEST_F(ContextTest, DerivedCachesExposeRingHelpers) {
  auto ctx = MakeRingContext(ContextBasisSet().size());

  // Test q() accessor
  const auto &q = ctx->residue_operators();
  EXPECT_EQ(q.size(), ContextBasisSet().size());
  for (size_t i = 0; i < ContextBasisSet().size(); ++i) {
    EXPECT_EQ(q[i].P(), ContextBasisSet()[i]);
  }

  // Test rns() accessor
  const auto &rns = ctx->rns();
  EXPECT_NE(rns, nullptr);

  // Test ops() accessor (NTT operators)
  const auto &ops = ctx->ops();
  EXPECT_EQ(ops.size(), ContextBasisSet().size());

  // Test bitrev() accessor
  const auto &bitrev = ctx->bitrev();
  EXPECT_EQ(bitrev.size(), ctx->degree());

  // Verify bit-reversal property
  for (size_t i = 0; i < ctx->degree(); ++i) {
    size_t reversed = bitrev[i];
    EXPECT_LT(reversed, ctx->degree());

    // Check that bitrev[bitrev[i]] has the bit-reversal property
    // This is a basic sanity check
    EXPECT_LT(bitrev[reversed], ctx->degree());
  }

  // Test inv_last_qi_mod_qj() accessor (for multi-modulus contexts)
  if (ContextBasisSet().size() > 1) {
    const auto &inv_last = ctx->inv_last_qi_mod_qj();
    EXPECT_EQ(inv_last.size(), ContextBasisSet().size() - 1);

    const auto &inv_last_shoup = ctx->inv_last_qi_mod_qj_shoup();
    EXPECT_EQ(inv_last_shoup.size(), ContextBasisSet().size() - 1);
  }
}

/**
 * @brief Test context equality and comparison.
 */
TEST_F(ContextTest, ContextValueEquality) {
  auto ctx1 = MakeRingContext(ContextBasisSet().size());
  auto ctx2 = MakeRingContext(ContextBasisSet().size());

  // Different context objects with same parameters should be equal
  EXPECT_EQ(ctx1->residue_basis(), ctx2->residue_basis());
  EXPECT_EQ(ctx1->degree(), ctx2->degree());
  EXPECT_EQ(ctx1->modulus(), ctx2->modulus());

  // Test with different degrees
  auto ctx3 = Context::create(
      ::bfv::math::test::BuildContextChainFixture(ContextBasisSet().size(), 32),
      32);
  EXPECT_NE(ctx1->degree(), ctx3->degree());

  // Test with different moduli
  auto ctx4 = MakeRingContext(3);
  EXPECT_NE(ctx1->residue_basis().size(), ctx4->residue_basis().size());
  EXPECT_NE(ctx1->modulus(), ctx4->modulus());
}

/**
 * @brief Test context with large degree.
 */
TEST_F(ContextTest, LargeDegreeLayouts) {
  // Test with larger degrees that are still reasonable
  for (size_t degree : {1024, 2048, 4096}) {
    auto ctx = Context::create(
        ::bfv::math::test::BuildSingleResidueFixture(degree, 0x6c61726765ULL),
        degree);

    EXPECT_EQ(ctx->degree(), degree);
    EXPECT_EQ(ctx->residue_basis().size(), 1);
    EXPECT_EQ(ctx->residue_basis().size(), 1);

    // Check that internal structures are properly sized
    const auto &bitrev = ctx->bitrev();
    EXPECT_EQ(bitrev.size(), degree);

    const auto &ops = ctx->ops();
    EXPECT_EQ(ops.size(), 1);
  }
}

/**
 * @brief Test context memory management.
 */
TEST_F(ContextTest, ContextLifetimeAndChainOwnership) {
  // Test that contexts can be created and destroyed without issues
  for (int i = 0; i < 100; ++i) {
    auto ctx =
        Context::create({ContextBasisSet()[i % ContextBasisSet().size()]}, 16);
    EXPECT_EQ(ctx->degree(), 16);
    EXPECT_EQ(ctx->residue_basis().size(), 1);
    // Context should be automatically destroyed when going out of scope
  }

  // Test context chain memory management
  {
    auto ctx = Context::create(ContextBasisSet(), 16);
    auto next_ctx = ctx->lower_level();

    // Both contexts should be valid
    EXPECT_NE(ctx, nullptr);
    EXPECT_NE(next_ctx, nullptr);

    // Check that the chain is properly formed
    EXPECT_EQ(ctx->residue_basis().size(), ContextBasisSet().size());
    EXPECT_EQ(next_ctx->residue_basis().size(), ContextBasisSet().size() - 1);
  }
  // All contexts should be automatically destroyed here
}

/**
 * @brief Test context with specific moduli combinations.
 * Exactly matches  test_specific_moduli.
 */
TEST_F(ContextTest, SelectedLayouts) {
  std::vector<std::vector<uint64_t>> moduli_layouts = {
      {ContextBasisSet()[1], ContextBasisSet()[3]},
      {ContextBasisSet()[0], ContextBasisSet()[4], ContextBasisSet()[2]},
      {ContextBasisSet()[0]},
      {ContextBasisSet()[1]},
      {ContextBasisSet()[0], ContextBasisSet()[1]},
      {ContextBasisSet()[1], ContextBasisSet()[2]},
      ContextBasisSet()};

  for (const auto &moduli_layout : moduli_layouts) {
    auto ctx = Context::create(moduli_layout, 16);

    EXPECT_EQ(ctx->residue_basis().size(), moduli_layout.size());
    EXPECT_EQ(ctx->degree(), 16);

    // Check that moduli match
    for (size_t i = 0; i < moduli_layout.size(); ++i) {
      EXPECT_EQ(ctx->residue_basis()[i], moduli_layout[i]);
    }

    // Check modulus product
    ::bfv::math::rns::BigUint expected_modulus(1);
    for (auto m : moduli_layout) {
      expected_modulus *= ::bfv::math::rns::BigUint(m);
    }
    EXPECT_EQ(ctx->modulus(), expected_modulus);

    // Check context chain
    if (moduli_layout.size() > 1) {
      EXPECT_NE(ctx->lower_level(), nullptr);
      EXPECT_EQ(ctx->lower_level()->residue_basis().size(),
                moduli_layout.size() - 1);
    } else {
      EXPECT_EQ(ctx->lower_level(), nullptr);
    }
  }
}

}  // namespace bfv::math::rq
