#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include "math/biguint.h"
#include "math/context.h"
#include "math/poly.h"
#include "math/representation.h"
#include "math/test_support.h"

namespace bfv::math::rq {

namespace {

constexpr size_t kFixtureDegree = 16;

const std::vector<uint64_t> &ConversionFixtureBasis() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x636f6e765f626173ULL, 5,
                                                    kFixtureDegree, 53);
  return basis;
}

}  // namespace

class PolyConvertTest : public ::testing::Test {
 protected:
  void SetUp() override {
    rng_.seed(42);  // Fixed seed for reproducible tests
  }

  std::mt19937_64 rng_;
};

/**
 * @brief Test conversion from u64 vector.
 */
TEST_F(PolyConvertTest, FromVecU64) {
  for (auto modulus : ConversionFixtureBasis()) {
    auto ctx = Context::create({modulus}, kFixtureDegree);

    // Create test vector with values less than modulus
    std::vector<uint64_t> coeffs(kFixtureDegree);
    for (size_t i = 0; i < kFixtureDegree; ++i) {
      coeffs[i] = (i * 123456789ULL) % modulus;
    }

    // Test all representations
    for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                      Representation::NttShoup}) {
      auto p = Poly::from_u64_vector(coeffs, ctx, false, repr);
      EXPECT_EQ(p.representation(), repr);
      EXPECT_EQ(p.ctx(), ctx);

      // Convert back and verify
      if (repr == Representation::PowerBasis) {
        auto converted_coeffs = p.to_u64_vector();
        EXPECT_EQ(converted_coeffs, coeffs);
      } else {
        // For NTT representations, convert to PowerBasis first
        auto p_copy = p;
        p_copy.change_representation(Representation::PowerBasis);
        auto converted_coeffs = p_copy.to_u64_vector();
        EXPECT_EQ(converted_coeffs, coeffs);
      }
    }

    // Test with variable time flag
    auto p_var_time =
        Poly::from_u64_vector(coeffs, ctx, true, Representation::PowerBasis);
    EXPECT_EQ(p_var_time.representation(), Representation::PowerBasis);
    EXPECT_EQ(p_var_time.ctx(), ctx);
  }

  // Test with multiple moduli
  auto ctx = Context::create(ConversionFixtureBasis(), kFixtureDegree);

  // Create flattened coefficient vector (5 moduli * 16 coefficients each)
  std::vector<uint64_t> coeffs(ConversionFixtureBasis().size() *
                               kFixtureDegree);
  for (size_t mod_idx = 0; mod_idx < ConversionFixtureBasis().size();
       ++mod_idx) {
    for (size_t coeff_idx = 0; coeff_idx < kFixtureDegree; ++coeff_idx) {
      coeffs[mod_idx * kFixtureDegree + coeff_idx] =
          (coeff_idx * 987654321ULL) % ConversionFixtureBasis()[mod_idx];
    }
  }

  auto p =
      Poly::from_u64_vector(coeffs, ctx, false, Representation::PowerBasis);
  auto converted_coeffs = p.to_u64_vector();
  EXPECT_EQ(converted_coeffs, coeffs);

  // Test error cases
  std::vector<uint64_t> wrong_size_coeffs(15);  // Wrong size
  EXPECT_THROW(Poly::from_u64_vector(wrong_size_coeffs, ctx, false,
                                     Representation::PowerBasis),
               DefaultException);

  std::vector<uint64_t> too_large_coeffs(
      16, ConversionFixtureBasis()[0]);  // Coefficients >= modulus
  auto single_ctx =
      Context::create({ConversionFixtureBasis()[0]}, kFixtureDegree);
  EXPECT_THROW(Poly::from_u64_vector(too_large_coeffs, single_ctx, false,
                                     Representation::PowerBasis),
               DefaultException);
}

/**
 * @brief Test conversion from i64 vector.
 */
TEST_F(PolyConvertTest, FromVecI64) {
  for (auto modulus : ConversionFixtureBasis()) {
    auto ctx = Context::create({modulus}, kFixtureDegree);

    // Create test vector with positive and negative values
    std::vector<int64_t> coeffs(kFixtureDegree);
    for (size_t i = 0; i < kFixtureDegree; ++i) {
      int64_t val = static_cast<int64_t>((i * 123456789ULL) % (modulus / 2));
      coeffs[i] = (i % 2 == 0) ? val : -val;  // Alternate positive/negative
    }

    // Only PowerBasis representation is supported for i64 input
    auto p =
        Poly::from_i64_vector(coeffs, ctx, false, Representation::PowerBasis);
    EXPECT_EQ(p.representation(), Representation::PowerBasis);
    EXPECT_EQ(p.ctx(), ctx);

    // Convert back and verify
    auto converted_coeffs = p.to_u64_vector();
    for (size_t i = 0; i < kFixtureDegree; ++i) {
      uint64_t expected;
      if (coeffs[i] >= 0) {
        expected = static_cast<uint64_t>(coeffs[i]);
      } else {
        expected = modulus - static_cast<uint64_t>(-coeffs[i]);
      }
      EXPECT_EQ(converted_coeffs[i], expected);
    }

    // Test with variable time flag
    auto p_var_time =
        Poly::from_i64_vector(coeffs, ctx, true, Representation::PowerBasis);
    EXPECT_EQ(p_var_time.representation(), Representation::PowerBasis);
    EXPECT_EQ(p_var_time.ctx(), ctx);
  }

  // Test with multiple moduli
  auto ctx = Context::create(ConversionFixtureBasis(), kFixtureDegree);

  std::vector<int64_t> coeffs(kFixtureDegree);
  for (size_t i = 0; i < kFixtureDegree; ++i) {
    coeffs[i] = static_cast<int64_t>(i) - 8;  // Range from -8 to 7
  }

  auto p =
      Poly::from_i64_vector(coeffs, ctx, false, Representation::PowerBasis);
  auto converted_coeffs = p.to_u64_vector();

  // Verify conversion for each modulus
  for (size_t mod_idx = 0; mod_idx < ConversionFixtureBasis().size();
       ++mod_idx) {
    for (size_t coeff_idx = 0; coeff_idx < kFixtureDegree; ++coeff_idx) {
      uint64_t expected;
      if (coeffs[coeff_idx] >= 0) {
        expected = static_cast<uint64_t>(coeffs[coeff_idx]);
      } else {
        expected = ConversionFixtureBasis()[mod_idx] -
                   static_cast<uint64_t>(-coeffs[coeff_idx]);
      }
      EXPECT_EQ(converted_coeffs[mod_idx * kFixtureDegree + coeff_idx],
                expected);
    }
  }

  // Test error cases
  EXPECT_THROW(Poly::from_i64_vector(coeffs, ctx, false, Representation::Ntt),
               DefaultException);
  EXPECT_THROW(
      Poly::from_i64_vector(coeffs, ctx, false, Representation::NttShoup),
      DefaultException);

  std::vector<int64_t> wrong_size_coeffs(15);
  EXPECT_THROW(Poly::from_i64_vector(wrong_size_coeffs, ctx, false,
                                     Representation::PowerBasis),
               DefaultException);

  // Test with values too large
  std::vector<int64_t> too_large_coeffs(
      16, static_cast<int64_t>(ConversionFixtureBasis()[0]));
  auto single_ctx =
      Context::create({ConversionFixtureBasis()[0]}, kFixtureDegree);
  EXPECT_THROW(Poly::from_i64_vector(too_large_coeffs, single_ctx, false,
                                     Representation::PowerBasis),
               DefaultException);
}

/**
 * @brief Test conversion from BigUint vector.
 */
TEST_F(PolyConvertTest, FromVecBigUint) {
  for (auto modulus : ConversionFixtureBasis()) {
    auto ctx = Context::create({modulus}, kFixtureDegree);

    // Create test vector of BigUints
    std::vector<::bfv::math::rns::BigUint> coeffs(kFixtureDegree);
    for (size_t i = 0; i < kFixtureDegree; ++i) {
      coeffs[i] = ::bfv::math::rns::BigUint((i * 987654321ULL) % modulus);
    }

    // Test all representations
    for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                      Representation::NttShoup}) {
      auto p = Poly::from_biguint_vector(coeffs, ctx, false, repr);
      EXPECT_EQ(p.representation(), repr);
      EXPECT_EQ(p.ctx(), ctx);

      // Convert back and verify
      auto converted_coeffs = p.to_biguint_vector();
      EXPECT_EQ(converted_coeffs.size(), coeffs.size());
      for (size_t i = 0; i < coeffs.size(); ++i) {
        EXPECT_EQ(converted_coeffs[i], coeffs[i]);
      }
    }

    // Test with variable time flag
    auto p_var_time = Poly::from_biguint_vector(coeffs, ctx, true,
                                                Representation::PowerBasis);
    EXPECT_EQ(p_var_time.representation(), Representation::PowerBasis);
    EXPECT_EQ(p_var_time.ctx(), ctx);
  }

  // Test with multiple moduli
  auto ctx = Context::create(ConversionFixtureBasis(), kFixtureDegree);

  std::vector<::bfv::math::rns::BigUint> coeffs(kFixtureDegree);
  for (size_t i = 0; i < kFixtureDegree; ++i) {
    // Create BigUint that's larger than any single modulus
    ::bfv::math::rns::BigUint big_val(ConversionFixtureBasis()[0]);
    big_val *= ::bfv::math::rns::BigUint(ConversionFixtureBasis()[1]);
    big_val += ::bfv::math::rns::BigUint(i * 12345ULL);
    coeffs[i] = big_val;
  }

  auto p =
      Poly::from_biguint_vector(coeffs, ctx, false, Representation::PowerBasis);
  auto converted_coeffs = p.to_biguint_vector();

  // Should be equal after RNS projection and reconstruction
  EXPECT_EQ(converted_coeffs.size(), coeffs.size());
  for (size_t i = 0; i < coeffs.size(); ++i) {
    // Reduce coeffs[i] modulo the context modulus for comparison
    auto reduced = coeffs[i] % ctx->modulus();
    EXPECT_EQ(converted_coeffs[i], reduced);
  }

  // Test error cases
  std::vector<::bfv::math::rns::BigUint> wrong_size_coeffs(15);
  EXPECT_THROW(Poly::from_biguint_vector(wrong_size_coeffs, ctx, false,
                                         Representation::PowerBasis),
               DefaultException);
}

/**
 * @brief Test conversion to BigUint vector.
 */
TEST_F(PolyConvertTest, ToVecBigUint) {
  for (auto modulus : ConversionFixtureBasis()) {
    auto ctx = Context::create({modulus}, kFixtureDegree);

    for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                      Representation::NttShoup}) {
      auto p = Poly::random(ctx, repr, rng_);
      auto biguint_vec = p.to_biguint_vector();

      EXPECT_EQ(biguint_vec.size(), kFixtureDegree);

      // All values should be less than the modulus
      for (const auto &val : biguint_vec) {
        EXPECT_LT(val, ::bfv::math::rns::BigUint(modulus));
      }

      // Convert back and verify
      auto p2 = Poly::from_biguint_vector(biguint_vec, ctx, false,
                                          Representation::PowerBasis);
      if (repr == Representation::PowerBasis) {
        EXPECT_EQ(p, p2);
      } else {
        auto p_copy = p;
        p_copy.change_representation(Representation::PowerBasis);
        EXPECT_EQ(p_copy, p2);
      }
    }
  }

  // Test with multiple moduli
  auto ctx = Context::create(ConversionFixtureBasis(), kFixtureDegree);

  for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                    Representation::NttShoup}) {
    auto p = Poly::random(ctx, repr, rng_);
    auto biguint_vec = p.to_biguint_vector();

    EXPECT_EQ(biguint_vec.size(), kFixtureDegree);

    // All values should be less than the context modulus
    for (const auto &val : biguint_vec) {
      EXPECT_LT(val, ctx->modulus());
    }

    // Convert back and verify
    auto p2 = Poly::from_biguint_vector(biguint_vec, ctx, false,
                                        Representation::PowerBasis);
    if (repr == Representation::PowerBasis) {
      EXPECT_EQ(p, p2);
    } else {
      auto p_copy = p;
      p_copy.change_representation(Representation::PowerBasis);
      EXPECT_EQ(p_copy, p2);
    }
  }
}

/**
 * @brief Test round-trip conversions.
 */
TEST_F(PolyConvertTest, RoundTripConversions) {
  auto ctx = Context::create(ConversionFixtureBasis(), kFixtureDegree);

  // Test u64 vector round trip
  std::vector<uint64_t> original_u64(ConversionFixtureBasis().size() *
                                     kFixtureDegree);
  for (size_t i = 0; i < original_u64.size(); ++i) {
    original_u64[i] =
        (i * 123456789ULL) % ConversionFixtureBasis()[i / kFixtureDegree];
  }

  auto p1 = Poly::from_u64_vector(original_u64, ctx, false,
                                  Representation::PowerBasis);
  auto converted_u64 = p1.to_u64_vector();
  EXPECT_EQ(converted_u64, original_u64);

  // Test BigUint vector round trip
  std::vector<::bfv::math::rns::BigUint> original_biguint(kFixtureDegree);
  for (size_t i = 0; i < kFixtureDegree; ++i) {
    original_biguint[i] = ::bfv::math::rns::BigUint(i * 987654321ULL);
  }

  auto p2 = Poly::from_biguint_vector(original_biguint, ctx, false,
                                      Representation::PowerBasis);
  auto converted_biguint = p2.to_biguint_vector();
  EXPECT_EQ(converted_biguint.size(), original_biguint.size());
  for (size_t i = 0; i < original_biguint.size(); ++i) {
    // Should be equal after modular reduction
    auto expected = original_biguint[i] % ctx->modulus();
    EXPECT_EQ(converted_biguint[i], expected);
  }

  // Test i64 vector round trip (only for small values)
  std::vector<int64_t> original_i64(kFixtureDegree);
  for (size_t i = 0; i < kFixtureDegree; ++i) {
    original_i64[i] = static_cast<int64_t>(i) - 8;  // Range from -8 to 7
  }

  auto p3 = Poly::from_i64_vector(original_i64, ctx, false,
                                  Representation::PowerBasis);
  auto converted_u64_from_i64 = p3.to_u64_vector();

  // Verify the conversion
  for (size_t mod_idx = 0; mod_idx < ConversionFixtureBasis().size();
       ++mod_idx) {
    for (size_t coeff_idx = 0; coeff_idx < kFixtureDegree; ++coeff_idx) {
      uint64_t expected;
      if (original_i64[coeff_idx] >= 0) {
        expected = static_cast<uint64_t>(original_i64[coeff_idx]);
      } else {
        expected = ConversionFixtureBasis()[mod_idx] -
                   static_cast<uint64_t>(-original_i64[coeff_idx]);
      }
      EXPECT_EQ(converted_u64_from_i64[mod_idx * kFixtureDegree + coeff_idx],
                expected);
    }
  }
}

/**
 * @brief Test conversion with different representations.
 */
TEST_F(PolyConvertTest, ConversionWithRepresentations) {
  auto ctx = Context::create(ConversionFixtureBasis(), kFixtureDegree);

  // Create original polynomial in PowerBasis
  std::vector<uint64_t> coeffs(ConversionFixtureBasis().size() *
                               kFixtureDegree);
  for (size_t i = 0; i < coeffs.size(); ++i) {
    coeffs[i] = (i * 555555ULL) % ConversionFixtureBasis()[i / kFixtureDegree];
  }

  auto p_power =
      Poly::from_u64_vector(coeffs, ctx, false, Representation::PowerBasis);

  // Convert to different representations and back
  for (auto target_repr : {Representation::Ntt, Representation::NttShoup}) {
    // Create polynomial directly in target representation
    auto p_target = Poly::from_u64_vector(coeffs, ctx, false, target_repr);

    // Convert to PowerBasis and compare
    auto p_target_copy = p_target;
    p_target_copy.change_representation(Representation::PowerBasis);
    EXPECT_EQ(p_target_copy, p_power);

    // Convert PowerBasis to target representation and compare
    auto p_power_copy = p_power;
    p_power_copy.change_representation(target_repr);
    EXPECT_EQ(p_power_copy, p_target);

    // Test BigUint conversion consistency
    auto biguint_power = p_power.to_biguint_vector();
    auto biguint_target = p_target.to_biguint_vector();
    EXPECT_EQ(biguint_power, biguint_target);
  }
}

/**
 * @brief Test error handling in conversions.
 */
TEST_F(PolyConvertTest, ConversionErrors) {
  auto ctx = Context::create({ConversionFixtureBasis()[0]}, kFixtureDegree);

  // Test wrong vector sizes
  std::vector<uint64_t> wrong_size_u64(15);
  EXPECT_THROW(Poly::from_u64_vector(wrong_size_u64, ctx, false,
                                     Representation::PowerBasis),
               DefaultException);

  std::vector<int64_t> wrong_size_i64(17);
  EXPECT_THROW(Poly::from_i64_vector(wrong_size_i64, ctx, false,
                                     Representation::PowerBasis),
               DefaultException);

  std::vector<::bfv::math::rns::BigUint> wrong_size_biguint(8);
  EXPECT_THROW(Poly::from_biguint_vector(wrong_size_biguint, ctx, false,
                                         Representation::PowerBasis),
               DefaultException);

  // Test coefficients too large
  std::vector<uint64_t> too_large_u64(kFixtureDegree,
                                      ConversionFixtureBasis()[0]);
  EXPECT_THROW(Poly::from_u64_vector(too_large_u64, ctx, false,
                                     Representation::PowerBasis),
               DefaultException);

  std::vector<int64_t> too_large_i64(
      kFixtureDegree, static_cast<int64_t>(ConversionFixtureBasis()[0]));
  EXPECT_THROW(Poly::from_i64_vector(too_large_i64, ctx, false,
                                     Representation::PowerBasis),
               DefaultException);

  // Test i64 with non-PowerBasis representations
  std::vector<int64_t> valid_i64(kFixtureDegree, 1);
  EXPECT_THROW(
      Poly::from_i64_vector(valid_i64, ctx, false, Representation::Ntt),
      DefaultException);
  EXPECT_THROW(
      Poly::from_i64_vector(valid_i64, ctx, false, Representation::NttShoup),
      DefaultException);
}

/**
 * @brief Test conversion with zero polynomials.
 */
TEST_F(PolyConvertTest, ZeroPolynomialConversions) {
  auto ctx = Context::create(ConversionFixtureBasis(), kFixtureDegree);

  // Test zero u64 vector
  std::vector<uint64_t> zero_u64(
      ConversionFixtureBasis().size() * kFixtureDegree, 0);
  auto p_zero_u64 =
      Poly::from_u64_vector(zero_u64, ctx, false, Representation::PowerBasis);
  auto zero_poly = Poly::zero(ctx, Representation::PowerBasis);
  EXPECT_EQ(p_zero_u64, zero_poly);

  // Test zero i64 vector
  std::vector<int64_t> zero_i64(kFixtureDegree, 0);
  auto p_zero_i64 =
      Poly::from_i64_vector(zero_i64, ctx, false, Representation::PowerBasis);
  EXPECT_EQ(p_zero_i64, zero_poly);

  // Test zero BigUint vector
  std::vector<::bfv::math::rns::BigUint> zero_biguint(
      kFixtureDegree, ::bfv::math::rns::BigUint::zero());
  auto p_zero_biguint = Poly::from_biguint_vector(zero_biguint, ctx, false,
                                                  Representation::PowerBasis);
  EXPECT_EQ(p_zero_biguint, zero_poly);

  // Test conversions from zero polynomial
  auto converted_u64 = zero_poly.to_u64_vector();
  EXPECT_EQ(converted_u64, zero_u64);

  auto converted_biguint = zero_poly.to_biguint_vector();
  EXPECT_EQ(converted_biguint, zero_biguint);
}

}  // namespace bfv::math::rq
