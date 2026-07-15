#include "math/basis_mapper.h"

#include <gtest/gtest.h>

#include <iostream>

#include "math/biguint.h"
#include "math/context.h"
#include "math/poly.h"
#include "math/scaling_factor.h"
#include "math/test_support.h"

using namespace bfv::math::rq;
using namespace bfv::math::rns;

namespace {

const std::vector<uint64_t> &MapperFixtureBasis() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x6d61705f66697874ULL, 5,
                                                    16, 52);
  return basis;
}

const std::vector<uint64_t> &MapperBatchFixtureBasis() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x6d61705f62617463ULL, 6,
                                                    16, 56);
  return basis;
}

}  // namespace

class BasisMapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
    const auto &basis = MapperFixtureBasis();
    std::vector<uint64_t> from_moduli = {basis[0], basis[1], basis[2]};
    std::vector<uint64_t> to_moduli = {basis[0], basis[3], basis[4]};

    from_ctx = Context::create_arc(from_moduli, 16);
    to_ctx = Context::create_arc(to_moduli, 16);
  }

  std::shared_ptr<Context> from_ctx;
  std::shared_ptr<Context> to_ctx;
};

TEST_F(BasisMapperTest, CreateBasisMapper) {
  BigUint numerator(1);
  BigUint denominator(1);
  ScalingFactor factor(numerator, denominator);

  auto mapper = BasisMapper::create(from_ctx, to_ctx, factor);
  ASSERT_NE(mapper, nullptr);
}

TEST_F(BasisMapperTest, CreateBasisMapperWithDifferentDegrees) {
  std::vector<uint64_t> different_moduli =
      ::bfv::math::test::BuildSingleResidueFixture(32, 0x6d61707032ULL);
  auto different_ctx = Context::create_arc(different_moduli, 32);

  BigUint numerator(1);
  BigUint denominator(1);
  ScalingFactor factor(numerator, denominator);

  EXPECT_THROW(BasisMapper::create(from_ctx, different_ctx, factor),
               std::runtime_error);
}

TEST_F(BasisMapperTest, MapZeroPolynomial) {
  BigUint numerator(1);
  BigUint denominator(1);
  ScalingFactor factor(numerator, denominator);

  auto mapper = BasisMapper::create(from_ctx, to_ctx, factor);
  auto poly = Poly::zero(from_ctx, Representation::PowerBasis);

  auto mapped_poly = mapper->map(poly);
  EXPECT_EQ(mapped_poly.ctx(), to_ctx);
  EXPECT_EQ(mapped_poly.representation(), Representation::PowerBasis);
}

TEST_F(BasisMapperTest, RejectMismatchedSourceContext) {
  BigUint numerator(1);
  BigUint denominator(1);
  ScalingFactor factor(numerator, denominator);

  auto mapper = BasisMapper::create(from_ctx, to_ctx, factor);
  auto poly = Poly::zero(to_ctx, Representation::PowerBasis);

  EXPECT_THROW(mapper->map(poly), std::runtime_error);
}

TEST_F(BasisMapperTest, EqualityComparison) {
  BigUint numerator(1);
  BigUint denominator(1);
  ScalingFactor factor(numerator, denominator);

  auto mapper1 = BasisMapper::create(from_ctx, to_ctx, factor);
  auto mapper2 = BasisMapper::create(from_ctx, to_ctx, factor);

  EXPECT_EQ(*mapper1, *mapper2);
  EXPECT_FALSE(*mapper1 != *mapper2);
}

TEST_F(BasisMapperTest, PreserveZeroCoefficientsAfterMapping) {
  BigUint numerator(1);
  BigUint denominator(1);
  ScalingFactor factor(numerator, denominator);
  auto mapper = BasisMapper::create(from_ctx, to_ctx, factor);

  auto poly = Poly::zero(from_ctx, Representation::PowerBasis);

  auto mapped_poly = mapper->map(poly);
  EXPECT_EQ(mapped_poly.ctx(), to_ctx);

  auto mapped_biguint = mapped_poly.to_biguint_vector();
  for (const auto &coeff : mapped_biguint) {
    EXPECT_EQ(coeff, BigUint(0));
  }
}

TEST_F(BasisMapperTest, MappingPreservesSharedPrefixAndNonZeroOutput) {
  BigUint numerator(1);
  BigUint denominator(1);
  ScalingFactor factor(numerator, denominator);
  auto mapper = BasisMapper::create(from_ctx, to_ctx, factor);

  std::mt19937_64 rng(42);
  auto poly = Poly::random(from_ctx, Representation::PowerBasis, rng);

  auto mapped_poly = mapper->map(poly);
  bool saw_non_zero = false;
  for (const auto &coeff : mapped_poly.to_biguint_vector()) {
    if (coeff != BigUint(0)) {
      saw_non_zero = true;
      break;
    }
  }

  EXPECT_EQ(mapped_poly.ctx(), to_ctx);
  EXPECT_TRUE(saw_non_zero);

  const size_t degree = from_ctx->degree();
  for (size_t i = 0; i < degree; ++i) {
    EXPECT_EQ(mapped_poly.data(0)[i], poly.data(0)[i]) << "coeff=" << i;
  }
}

TEST_F(BasisMapperTest, MappingIsRepresentationInvariantAcrossAliases) {
  BigUint numerator(1);
  BigUint denominator(1);
  ScalingFactor factor(numerator, denominator);
  auto mapper = BasisMapper::create(from_ctx, to_ctx, factor);

  std::mt19937_64 rng(42);
  for (int trial = 0; trial < 8; ++trial) {
    auto poly = Poly::random(from_ctx, Representation::PowerBasis, rng);
    auto mapped_power = mapper->map(poly);
    auto mapped_alias = poly.remap_to_basis(*mapper);

    auto poly_ntt = poly;
    poly_ntt.change_representation(Representation::Ntt);
    auto mapped_ntt = mapper->map(poly_ntt);
    mapped_ntt.change_representation(Representation::PowerBasis);

    EXPECT_EQ(mapped_power.ctx(), to_ctx);
    EXPECT_EQ(mapped_alias.ctx(), to_ctx);
    EXPECT_EQ(mapped_ntt.ctx(), to_ctx);
    EXPECT_EQ(mapped_power.to_biguint_vector(),
              mapped_alias.to_biguint_vector())
        << "alias mismatch at trial=" << trial;
    EXPECT_EQ(mapped_power.to_biguint_vector(), mapped_ntt.to_biguint_vector())
        << "representation mismatch at trial=" << trial;
  }
}

TEST(BasisMapperBatchTest, MapManyMatchesSingleMap) {
  const auto &basis = MapperBatchFixtureBasis();
  std::vector<uint64_t> from_moduli = {
      basis[0],
      basis[1],
      basis[2],
      basis[3],
  };
  std::vector<uint64_t> to_moduli = {
      basis[0],
      basis[4],
  };

  auto from_ctx = Context::create_arc(from_moduli, 16);
  auto to_ctx = Context::create_arc(to_moduli, 16);
  ScalingFactor factor =
      ::bfv::math::test::BuildDerivedTransferFactor(from_ctx->modulus());
  auto mapper = BasisMapper::create(from_ctx, to_ctx, factor);

  std::mt19937_64 rng(20260312);
  std::vector<Poly> polys;
  polys.reserve(3);
  for (size_t i = 0; i < 3; ++i) {
    polys.push_back(Poly::random(from_ctx, Representation::PowerBasis, rng));
  }

  auto batch_out = mapper->map_many(polys);
  ASSERT_EQ(batch_out.size(), polys.size());

  for (size_t i = 0; i < polys.size(); ++i) {
    auto single_out = mapper->map(polys[i]);
    EXPECT_EQ(batch_out[i].representation(), single_out.representation());
    EXPECT_EQ(batch_out[i].ctx(), single_out.ctx());
    auto batch_coeffs = batch_out[i].to_biguint_vector();
    auto single_coeffs = single_out.to_biguint_vector();
    EXPECT_EQ(batch_coeffs, single_coeffs) << "mismatch at poly " << i;
  }
}
