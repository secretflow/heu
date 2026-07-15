#include <gtest/gtest.h>

#include <array>
#include <random>
#include <stdexcept>
#include <vector>

#include "math/biguint.h"
#include "math/modulus.h"
#include "math/residue_transfer_engine.h"
#include "math/rns_context.h"
#include "math/scaling_factor.h"
#include "math/test_support.h"
#include "util/arena_allocator.h"

using namespace bfv::math::rns;
using namespace bfv::math::zq;

namespace {

const std::vector<uint64_t> &ExampleResidueBasis() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x726e735f6578616dULL, 3, 8,
                                                    12);
  return basis;
}

std::vector<uint64_t> BuildTinyTransferSourceBasis() {
  return ::bfv::math::test::GenerateTaggedResidueBasis(0x72736e5f73696eULL, 2,
                                                       8, 12);
}

std::vector<uint64_t> BuildTinyTransferTargetBasis() {
  return ::bfv::math::test::GenerateTaggedResidueBasis(0x72736e5f736f75ULL, 1,
                                                       8, 11);
}

std::vector<uint64_t> BuildTinyBatchSourceBasis() {
  return ::bfv::math::test::GenerateTaggedResidueBasis(0x72736e5f62696eULL, 2,
                                                       8, 12);
}

std::vector<uint64_t> BuildTinyBatchTargetBasis() {
  return ::bfv::math::test::GenerateTaggedResidueBasis(0x72736e5f626f75ULL, 2,
                                                       8, 11);
}

const std::vector<uint64_t> &BuildTransferSourceBasis() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x72736e5f7472696eULL, 4,
                                                    16, 58);
  return basis;
}

const std::vector<uint64_t> &BuildTransferTargetBasis() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x72736e5f74726f75ULL, 2,
                                                    16, 60);
  return basis;
}

const std::vector<uint64_t> &BuildPostMultiplyTargetBasis() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x72736e5f706f7374ULL, 3,
                                                    16, 59);
  return basis;
}

const std::vector<uint64_t> &BuildPostMultiplyExtensionBasis() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x72736e5f65787472ULL, 1,
                                                    16, 55);
  return basis;
}

std::vector<uint64_t> ComputeReferenceResidues(
    const BigUint &value, const std::vector<uint64_t> &basis) {
  std::vector<uint64_t> residues;
  residues.reserve(basis.size());
  for (uint64_t modulus : basis) {
    residues.push_back((value % modulus).to_u64());
  }
  return residues;
}

uint64_t BasisProductOf(const std::vector<uint64_t> &basis) {
  uint64_t basis_product = 1;
  for (uint64_t modulus : basis) {
    basis_product *= modulus;
  }
  return basis_product;
}

}  // namespace

TEST(RnsTest, ResidueBasisValidation) {
  EXPECT_NO_THROW(RnsContext({2}));
  EXPECT_NO_THROW(RnsContext({2, 3}));
  EXPECT_NO_THROW({
    auto ctx = RnsContext(ExampleResidueBasis());
    (void)ctx;
  });

  EXPECT_THROW(RnsContext({}), std::runtime_error);
  EXPECT_THROW(RnsContext({2, 4}), std::runtime_error);
  EXPECT_THROW(RnsContext({2, 3, 5, 30}), std::runtime_error);
}

TEST(RnsTest, LiftTermsStayAccessible) {
  RnsContext rns(ExampleResidueBasis());

  for (size_t i = 0; i < 3; ++i) {
    auto gi = rns.get_garner(i);
    EXPECT_TRUE(gi != BigUint::zero());
    EXPECT_EQ(gi, rns.get_garner(i));
  }
  EXPECT_THROW(rns.get_garner(3), std::out_of_range);
}

TEST(RnsTest, BasisProductMatchesCompositeModulus) {
  RnsContext rns1({2});
  EXPECT_EQ(rns1.modulus(), BigUint(2));

  RnsContext rns2({2, 5});
  EXPECT_EQ(rns2.modulus(), BigUint(2 * 5));

  RnsContext rns3(ExampleResidueBasis());
  EXPECT_EQ(rns3.modulus(), BigUint(BasisProductOf(ExampleResidueBasis())));
}

TEST(RnsTest, ProjectAndLiftRoundTripAcrossBasis) {
  RnsContext residue_context(ExampleResidueBasis());
  const uint64_t basis_product = BasisProductOf(ExampleResidueBasis());

  const std::vector<BigUint> sample_values = {
      BigUint(0), BigUint(ExampleResidueBasis()[0]),
      BigUint(ExampleResidueBasis()[1]), BigUint(ExampleResidueBasis()[2]),
      BigUint(basis_product - 1)};
  for (const auto &value : sample_values) {
    auto residues = residue_context.project(value);
    EXPECT_EQ(residues, ComputeReferenceResidues(value, ExampleResidueBasis()));
    EXPECT_EQ(residue_context.lift(residues), value);
  }

  std::mt19937_64 rng(20260314);
  for (int i = 0; i < 100; ++i) {
    BigUint sampled_value(rng() % basis_product);
    auto residues = residue_context.project(sampled_value);
    EXPECT_EQ(residue_context.lift(residues), sampled_value);
  }
}

TEST(RnsTest, ScalarTransferIntoSingleOutputBasis) {
  auto input_ctx = RnsContext::create(BuildTinyTransferSourceBasis());
  auto output_ctx = RnsContext::create(BuildTinyTransferTargetBasis());
  ScalingFactor scaling_factor(BigUint(output_ctx->moduli_u64()[0]),
                               BigUint(input_ctx->modulus()));
  ResidueTransferEngine transfer_engine(input_ctx, output_ctx, scaling_factor);

  const uint64_t input_value = 58 % input_ctx->moduli_u64()[0];
  const uint64_t source_modulus = input_ctx->modulus().to_u64();
  const uint64_t target_modulus = output_ctx->moduli_u64()[0];
  const uint64_t expected_value =
      ((input_value * target_modulus) + (source_modulus / 2)) / source_modulus;
  auto residues = input_ctx->project(BigUint(input_value));
  std::vector<uint64_t> output(1);
  transfer_engine.scale(residues, output, 0);
  EXPECT_EQ(output[0], expected_value % target_modulus);
}

TEST(RnsTest, MultiPolynomialTransferAcrossBases) {
  auto input_ctx = RnsContext::create(BuildTinyBatchSourceBasis());
  auto output_ctx = RnsContext::create(BuildTinyBatchTargetBasis());
  ScalingFactor identity_factor(BigUint(1), BigUint(1));
  ResidueTransferEngine transfer_engine(input_ctx, output_ctx, identity_factor);

  const uint64_t first_value = 10;
  const uint64_t second_value = 20;
  std::vector<std::vector<std::vector<uint64_t>>> input_polys(2);
  input_polys[0] = {{first_value % input_ctx->moduli_u64()[0],
                     first_value % input_ctx->moduli_u64()[1]}};
  input_polys[1] = {{second_value % input_ctx->moduli_u64()[0],
                     second_value % input_ctx->moduli_u64()[1]}};

  std::vector<std::vector<std::vector<uint64_t>>> output_polys;
  transfer_engine.scale_multi_poly(input_polys, output_polys, 0);

  EXPECT_EQ(output_polys.size(), 2);
  EXPECT_EQ(output_polys[0][0].size(), 2);
  EXPECT_EQ(output_polys[0][0][0], first_value % output_ctx->moduli_u64()[0]);
  EXPECT_EQ(output_polys[0][0][1], first_value % output_ctx->moduli_u64()[1]);
  EXPECT_EQ(output_polys[1][0][0], second_value % output_ctx->moduli_u64()[0]);
  EXPECT_EQ(output_polys[1][0][1], second_value % output_ctx->moduli_u64()[1]);
}

TEST(RnsTest, BatchTransferMatchesScalarReference) {
  const auto &from_basis = BuildTransferSourceBasis();
  const auto &to_basis = BuildTransferTargetBasis();
  auto from_ctx = RnsContext::create(from_basis);
  auto to_ctx = RnsContext::create(to_basis);
  ScalingFactor factor =
      ::bfv::math::test::BuildDerivedTransferFactor(from_ctx->modulus());
  ResidueTransferEngine transfer_engine(from_ctx, to_ctx, factor);

  constexpr size_t kCount = 64;
  std::vector<std::vector<uint64_t>> input_rows =
      ::bfv::math::test::MakeRandomResidueRows(from_ctx, kCount, 20260314);

  std::vector<const uint64_t *> input_ptrs(from_ctx->moduli_u64().size());
  for (size_t mod_idx = 0; mod_idx < input_rows.size(); ++mod_idx) {
    input_ptrs[mod_idx] = input_rows[mod_idx].data();
  }

  std::vector<std::vector<uint64_t>> batch_output_rows(
      to_ctx->moduli_u64().size(), std::vector<uint64_t>(kCount));
  std::vector<uint64_t *> output_ptrs(to_ctx->moduli_u64().size());
  for (size_t mod_idx = 0; mod_idx < batch_output_rows.size(); ++mod_idx) {
    output_ptrs[mod_idx] = batch_output_rows[mod_idx].data();
  }

  transfer_engine.scale_batch(input_ptrs, output_ptrs, kCount, 0);

  std::vector<uint64_t> scalar_in(from_ctx->moduli_u64().size());
  std::vector<uint64_t> scalar_out(to_ctx->moduli_u64().size());
  for (size_t c = 0; c < kCount; ++c) {
    for (size_t mod_idx = 0; mod_idx < input_rows.size(); ++mod_idx) {
      scalar_in[mod_idx] = input_rows[mod_idx][c];
    }
    std::fill(scalar_out.begin(), scalar_out.end(), 0);
    transfer_engine.scale(scalar_in, scalar_out, 0);
    for (size_t mod_idx = 0; mod_idx < batch_output_rows.size(); ++mod_idx) {
      EXPECT_EQ(batch_output_rows[mod_idx][c], scalar_out[mod_idx])
          << "coeff_index=" << c << " output_modulus=" << mod_idx;
    }
  }
}

TEST(RnsTest, PostMultiplyTransferMatchesScalarReference) {
  const auto &to_basis = BuildPostMultiplyTargetBasis();
  std::vector<uint64_t> from_basis = to_basis;
  const auto &extra_basis = BuildPostMultiplyExtensionBasis();
  from_basis.push_back(extra_basis.front());
  auto to_ctx = RnsContext::create(to_basis);
  auto from_ctx = RnsContext::create(from_basis);
  ScalingFactor factor =
      ::bfv::math::test::BuildDerivedTransferFactor(to_ctx->modulus());
  ResidueTransferEngine transfer_engine(from_ctx, to_ctx, factor);

  constexpr size_t kCount = 64;
  std::vector<std::vector<uint64_t>> input_rows =
      ::bfv::math::test::MakeRandomResidueRows(from_ctx, kCount, 20260315);

  std::vector<const uint64_t *> input_ptrs(from_ctx->moduli_u64().size());
  for (size_t mod_idx = 0; mod_idx < input_rows.size(); ++mod_idx) {
    input_ptrs[mod_idx] = input_rows[mod_idx].data();
  }

  std::vector<std::vector<uint64_t>> batch_output_rows(
      to_ctx->moduli_u64().size(), std::vector<uint64_t>(kCount));
  std::vector<uint64_t *> output_ptrs(to_ctx->moduli_u64().size());
  for (size_t mod_idx = 0; mod_idx < batch_output_rows.size(); ++mod_idx) {
    output_ptrs[mod_idx] = batch_output_rows[mod_idx].data();
  }

  transfer_engine.scale_batch(input_ptrs, output_ptrs, kCount, 0);

  std::vector<uint64_t> scalar_in(from_ctx->moduli_u64().size());
  std::vector<uint64_t> scalar_out(to_ctx->moduli_u64().size());
  for (size_t c = 0; c < kCount; ++c) {
    for (size_t mod_idx = 0; mod_idx < input_rows.size(); ++mod_idx) {
      scalar_in[mod_idx] = input_rows[mod_idx][c];
    }
    std::fill(scalar_out.begin(), scalar_out.end(), 0);
    transfer_engine.scale(scalar_in, scalar_out, 0);
    for (size_t mod_idx = 0; mod_idx < batch_output_rows.size(); ++mod_idx) {
      EXPECT_EQ(batch_output_rows[mod_idx][c], scalar_out[mod_idx])
          << "coeff_index=" << c << " output_modulus=" << mod_idx;
    }
  }
}
