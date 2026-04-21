#include "math/context_transfer.h"

#include <gtest/gtest.h>

#include <random>
#include <vector>

#include "math/biguint.h"
#include "math/context.h"
#include "math/poly.h"
#include "math/test_support.h"

using namespace bfv::math::rq;
using namespace bfv::math::rns;

namespace {

const std::vector<uint64_t> &TransferFixtureBasis() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x6374725f66697874ULL, 5,
                                                    16, 52);
  return basis;
}
}  // namespace

class ContextTransferTest : public ::testing::Test {
 protected:
  void SetUp() override {
    const auto &basis = TransferFixtureBasis();
    std::vector<uint64_t> source_moduli = {basis[0], basis[1]};
    std::vector<uint64_t> target_moduli = {basis[3], basis[4]};

    source_ctx = Context::create_arc(source_moduli, 16);
    target_ctx = Context::create_arc(target_moduli, 16);
  }

  std::shared_ptr<Context> source_ctx;
  std::shared_ptr<Context> target_ctx;
};

TEST_F(ContextTransferTest, CreateTransferRoute) {
  auto transfer = ContextTransfer::create(source_ctx, target_ctx);
  ASSERT_NE(transfer, nullptr);
}

TEST_F(ContextTransferTest, RejectMismatchedDegrees) {
  std::vector<uint64_t> different_moduli =
      ::bfv::math::test::BuildSingleResidueFixture(32, 0x6374787472ULL);
  auto different_ctx = Context::create_arc(different_moduli, 32);

  EXPECT_THROW(ContextTransfer::create(source_ctx, different_ctx),
               std::runtime_error);
}

TEST_F(ContextTransferTest, TransferZeroPolynomial) {
  auto transfer = ContextTransfer::create(source_ctx, target_ctx);
  auto poly = Poly::zero(source_ctx, Representation::PowerBasis);

  auto transferred = transfer->apply(poly);
  EXPECT_EQ(transferred.ctx(), target_ctx);
  EXPECT_EQ(transferred.representation(), Representation::PowerBasis);
}

TEST_F(ContextTransferTest, RejectMismatchedSourceContext) {
  auto transfer = ContextTransfer::create(source_ctx, target_ctx);
  auto poly = Poly::zero(target_ctx, Representation::PowerBasis);

  EXPECT_THROW(transfer->apply(poly), std::runtime_error);
}

TEST_F(ContextTransferTest, EqualityComparison) {
  auto transfer1 = ContextTransfer::create(source_ctx, target_ctx);
  auto transfer2 = ContextTransfer::create(source_ctx, target_ctx);

  EXPECT_EQ(*transfer1, *transfer2);
  EXPECT_FALSE(*transfer1 != *transfer2);
}

TEST_F(ContextTransferTest, RemapToContextMatchesRoundedReference) {
  std::mt19937_64 rng(42);
  constexpr int kTrials = 100;

  auto transfer = ContextTransfer::create(source_ctx, target_ctx);

  for (int trial = 0; trial < kTrials; ++trial) {
    auto poly = Poly::random(source_ctx, Representation::PowerBasis, rng);
    auto source_coeffs = poly.to_biguint_vector();

    auto remapped = poly.remap_to_context(*transfer);
    auto remapped_coeffs = remapped.to_biguint_vector();
    auto expected = ::bfv::math::test::BuildRoundedTransferReference(
        source_coeffs, source_ctx->modulus(), target_ctx->modulus());

    EXPECT_EQ(remapped.ctx(), target_ctx);
    ASSERT_EQ(expected.size(), remapped_coeffs.size());
    for (size_t i = 0; i < expected.size(); ++i) {
      EXPECT_EQ(expected[i], remapped_coeffs[i])
          << "Mismatch at coeff=" << i << " trial=" << trial;
    }
  }
}

TEST_F(ContextTransferTest, ApplyTransferMatchesRoundedReference) {
  std::mt19937_64 rng(42);
  constexpr int kTrials = 12;

  auto transfer = ContextTransfer::create(source_ctx, target_ctx);

  for (int trial = 0; trial < kTrials; ++trial) {
    auto poly = Poly::random(source_ctx, Representation::PowerBasis, rng);
    auto source_coeffs = poly.to_biguint_vector();

    auto transferred = transfer->apply(poly);
    auto transferred_coeffs = transferred.to_biguint_vector();
    auto expected = ::bfv::math::test::BuildRoundedTransferReference(
        source_coeffs, source_ctx->modulus(), target_ctx->modulus());

    EXPECT_EQ(transferred.ctx(), target_ctx);
    ASSERT_EQ(expected.size(), transferred_coeffs.size());
    for (size_t i = 0; i < expected.size(); ++i) {
      EXPECT_EQ(expected[i], transferred_coeffs[i])
          << "Mismatch at coeff=" << i << " trial=" << trial;
    }
  }
}
