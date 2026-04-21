#include "poly_ops.h"

#include <gtest/gtest.h>

#include <array>
#include <functional>
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

const std::vector<uint64_t> &ArithmeticFixtureBasis() {
  static const std::vector<uint64_t> basis =
      ::bfv::math::test::GenerateTaggedResidueBasis(0x6f70735f61726974ULL, 5,
                                                    16, 53);
  return basis;
}

}  // namespace

class PolyOpsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    rng_.seed(42);  // Fixed seed for reproducible tests
  }

  std::mt19937_64 rng_;
};

/**
 * @brief Test polynomial addition.
 */
TEST_F(PolyOpsTest, Add) {
  for (auto modulus : ArithmeticFixtureBasis()) {
    auto ctx = Context::create({modulus}, 16);

    for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                      Representation::NttShoup}) {
      auto p = Poly::random(ctx, repr, rng_);
      auto q = Poly::random(ctx, repr, rng_);

      // Test addition
      auto r = p + q;
      EXPECT_EQ(r.representation(), repr);
      EXPECT_EQ(r.ctx(), ctx);

      // Test commutativity: p + q = q + p
      auto r2 = q + p;
      EXPECT_EQ(r, r2);

      // Test addition with zero
      auto zero = Poly::zero(ctx, repr);
      auto r3 = p + zero;
      EXPECT_EQ(r3, p);

      // Test in-place addition
      auto p_copy = p;
      p_copy += q;
      EXPECT_EQ(p_copy, r);
    }
  }

  // Test with multiple moduli
  auto ctx = Context::create(ArithmeticFixtureBasis(), 16);
  for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                    Representation::NttShoup}) {
    auto p = Poly::random(ctx, repr, rng_);
    auto q = Poly::random(ctx, repr, rng_);

    auto r = p + q;
    EXPECT_EQ(r.representation(), repr);
    EXPECT_EQ(r.ctx(), ctx);

    // Verify coefficient-wise addition
    const auto &p_coeffs = p.coefficients();
    const auto &q_coeffs = q.coefficients();
    const auto &r_coeffs = r.coefficients();

    for (size_t i = 0; i < p_coeffs.size(); ++i) {
      for (size_t j = 0; j < p_coeffs[i].size(); ++j) {
        uint64_t expected =
            (p_coeffs[i][j] + q_coeffs[i][j]) % ArithmeticFixtureBasis()[i];
        EXPECT_EQ(r_coeffs[i][j], expected);
      }
    }
  }
}

/**
 * @brief Test polynomial subtraction.
 */
TEST_F(PolyOpsTest, Sub) {
  for (auto modulus : ArithmeticFixtureBasis()) {
    auto ctx = Context::create({modulus}, 16);

    for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                      Representation::NttShoup}) {
      auto p = Poly::random(ctx, repr, rng_);
      auto q = Poly::random(ctx, repr, rng_);

      // Test subtraction
      auto r = p - q;
      EXPECT_EQ(r.representation(), repr);
      EXPECT_EQ(r.ctx(), ctx);

      // Test subtraction with zero
      auto zero = Poly::zero(ctx, repr);
      auto r2 = p - zero;
      EXPECT_EQ(r2, p);

      // Test subtraction from zero
      auto r3 = zero - p;
      EXPECT_EQ(r3, -p);

      // Test self-subtraction
      auto r4 = p - p;
      EXPECT_EQ(r4, zero);

      // Test in-place subtraction
      auto p_copy = p;
      p_copy -= q;
      EXPECT_EQ(p_copy, r);
    }
  }

  // Test with multiple moduli
  auto ctx = Context::create(ArithmeticFixtureBasis(), 16);
  for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                    Representation::NttShoup}) {
    auto p = Poly::random(ctx, repr, rng_);
    auto q = Poly::random(ctx, repr, rng_);

    auto r = p - q;
    EXPECT_EQ(r.representation(), repr);
    EXPECT_EQ(r.ctx(), ctx);

    // Verify coefficient-wise subtraction
    const auto &p_coeffs = p.coefficients();
    const auto &q_coeffs = q.coefficients();
    const auto &r_coeffs = r.coefficients();

    for (size_t i = 0; i < p_coeffs.size(); ++i) {
      for (size_t j = 0; j < p_coeffs[i].size(); ++j) {
        uint64_t expected =
            (p_coeffs[i][j] + ArithmeticFixtureBasis()[i] - q_coeffs[i][j]) %
            ArithmeticFixtureBasis()[i];
        EXPECT_EQ(r_coeffs[i][j], expected);
      }
    }
  }
}

/**
 * @brief Test polynomial negation.
 */
TEST_F(PolyOpsTest, Neg) {
  for (auto modulus : ArithmeticFixtureBasis()) {
    auto ctx = Context::create({modulus}, 16);

    for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                      Representation::NttShoup}) {
      auto p = Poly::random(ctx, repr, rng_);

      // Test negation
      auto neg_p = -p;
      EXPECT_EQ(neg_p.representation(), repr);
      EXPECT_EQ(neg_p.ctx(), ctx);

      // Test double negation
      auto double_neg = -neg_p;
      EXPECT_EQ(double_neg, p);

      // Test negation of zero
      auto zero = Poly::zero(ctx, repr);
      auto neg_zero = -zero;
      EXPECT_EQ(neg_zero, zero);

      // Test p + (-p) = 0
      auto sum = p + neg_p;
      EXPECT_EQ(sum, zero);
    }
  }

  // Test with multiple moduli
  auto ctx = Context::create(ArithmeticFixtureBasis(), 16);
  for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                    Representation::NttShoup}) {
    auto p = Poly::random(ctx, repr, rng_);
    auto neg_p = -p;

    // Verify coefficient-wise negation
    const auto &p_coeffs = p.coefficients();
    const auto &neg_coeffs = neg_p.coefficients();

    for (size_t i = 0; i < p_coeffs.size(); ++i) {
      for (size_t j = 0; j < p_coeffs[i].size(); ++j) {
        uint64_t expected = p_coeffs[i][j] == 0
                                ? 0
                                : ArithmeticFixtureBasis()[i] - p_coeffs[i][j];
        EXPECT_EQ(neg_coeffs[i][j], expected);
      }
    }
  }
}

/**
 * @brief Test polynomial multiplication.
 */
TEST_F(PolyOpsTest, Mul) {
  for (auto modulus : ArithmeticFixtureBasis()) {
    auto ctx = Context::create({modulus}, 16);

    // Test multiplication in different representations
    for (auto repr : {Representation::Ntt, Representation::NttShoup}) {
      auto p = Poly::random(ctx, repr, rng_);
      auto q = Poly::random(ctx, repr, rng_);

      // Test multiplication
      auto r = p * q;
      EXPECT_EQ(r.representation(), repr);
      EXPECT_EQ(r.ctx(), ctx);

      // Test commutativity: p * q = q * p
      auto r2 = q * p;
      EXPECT_EQ(r, r2);

      // Test multiplication with zero
      auto zero = Poly::zero(ctx, repr);
      auto r3 = p * zero;
      EXPECT_EQ(r3, zero);

      // Test multiplication with one (if we had a one polynomial)
      // Note: This would require creating a polynomial with coefficient 1

      // Test in-place multiplication
      auto p_copy = p;
      p_copy *= q;
      EXPECT_EQ(p_copy, r);
    }
  }

  // Test PowerBasis multiplication should fail
  auto ctx = Context::create({ArithmeticFixtureBasis()[0]}, 16);
  auto p = Poly::random(ctx, Representation::PowerBasis, rng_);
  auto q = Poly::random(ctx, Representation::PowerBasis, rng_);
  EXPECT_THROW(p * q, DefaultException);

  // Test with multiple moduli
  auto ctx_multi = Context::create(ArithmeticFixtureBasis(), 16);
  for (auto repr : {Representation::Ntt, Representation::NttShoup}) {
    auto p = Poly::random(ctx_multi, repr, rng_);
    auto q = Poly::random(ctx_multi, repr, rng_);

    auto r = p * q;
    EXPECT_EQ(r.representation(), repr);
    EXPECT_EQ(r.ctx(), ctx_multi);
  }
}

/**
 * @brief Test polynomial scalar multiplication.
 */
TEST_F(PolyOpsTest, MulScalar) {
  for (auto modulus : ArithmeticFixtureBasis()) {
    auto ctx = Context::create({modulus}, 16);

    for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                      Representation::NttShoup}) {
      auto p = Poly::random(ctx, repr, rng_);

      // Test multiplication by scalar
      ::bfv::math::rns::BigUint scalar(42);
      auto r = p * scalar;
      EXPECT_EQ(r.representation(), repr);
      EXPECT_EQ(r.ctx(), ctx);

      // Test multiplication by zero
      ::bfv::math::rns::BigUint zero_scalar(0);
      auto r2 = p * zero_scalar;
      auto zero_poly = Poly::zero(ctx, repr);
      EXPECT_EQ(r2, zero_poly);

      // Test multiplication by one
      ::bfv::math::rns::BigUint one_scalar(1);
      auto r3 = p * one_scalar;
      EXPECT_EQ(r3, p);

      // Test in-place scalar multiplication
      auto p_copy = p;
      p_copy *= scalar;
      EXPECT_EQ(p_copy, r);
    }
  }

  // Test with multiple moduli
  auto ctx = Context::create(ArithmeticFixtureBasis(), 16);
  for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                    Representation::NttShoup}) {
    auto p = Poly::random(ctx, repr, rng_);
    ::bfv::math::rns::BigUint scalar(123456789);

    auto r = p * scalar;
    EXPECT_EQ(r.representation(), repr);
    EXPECT_EQ(r.ctx(), ctx);

    // Verify coefficient-wise scalar multiplication
    const auto &p_coeffs = p.coefficients();
    const auto &r_coeffs = r.coefficients();

    for (size_t i = 0; i < p_coeffs.size(); ++i) {
      uint64_t scalar_mod = scalar.to_u64() % ArithmeticFixtureBasis()[i];
      for (size_t j = 0; j < p_coeffs[i].size(); ++j) {
        uint64_t expected =
            (p_coeffs[i][j] * scalar_mod) % ArithmeticFixtureBasis()[i];
        EXPECT_EQ(r_coeffs[i][j], expected);
      }
    }
  }
}

/**
 * @brief Test polynomial dot product.
 */
TEST_F(PolyOpsTest, DotProduct) {
  for (auto modulus : ArithmeticFixtureBasis()) {
    auto ctx = Context::create({modulus}, 16);

    // Test dot product in NTT representations
    for (auto repr : {Representation::Ntt, Representation::NttShoup}) {
      // Create vectors of polynomials
      std::vector<Poly> p_vec, q_vec;
      std::vector<std::reference_wrapper<const Poly>> p_refs, q_refs;

      for (int i = 0; i < 5; ++i) {
        p_vec.emplace_back(Poly::random(ctx, repr, rng_));
        q_vec.emplace_back(Poly::random(ctx, repr, rng_));
        p_refs.emplace_back(std::cref(p_vec.back()));
        q_refs.emplace_back(std::cref(q_vec.back()));
      }

      // Compute dot product
      auto dot_result = dot_product(p_refs, q_refs);
      EXPECT_EQ(dot_result.representation(), repr);
      EXPECT_EQ(dot_result.ctx(), ctx);

      // Compute reference result manually
      auto reference = Poly::zero(ctx, repr);
      for (size_t i = 0; i < p_vec.size(); ++i) {
        reference += p_vec[i] * q_vec[i];
      }

      EXPECT_EQ(dot_result, reference);
    }
  }

  // Test with empty vectors
  auto ctx = Context::create({ArithmeticFixtureBasis()[0]}, 16);
  std::vector<std::reference_wrapper<const Poly>> empty_p, empty_q;
  EXPECT_THROW(dot_product(empty_p, empty_q), DefaultException);

  // Test with mismatched vector sizes
  auto p = Poly::random(ctx, Representation::Ntt, rng_);
  auto q = Poly::random(ctx, Representation::Ntt, rng_);
  std::vector<std::reference_wrapper<const Poly>> p_single = {std::cref(p)};
  std::vector<std::reference_wrapper<const Poly>> q_double = {std::cref(q),
                                                              std::cref(q)};
  EXPECT_THROW(dot_product(p_single, q_double), DefaultException);

  // Test with multiple moduli
  auto ctx_multi = Context::create(ArithmeticFixtureBasis(), 16);
  for (auto repr : {Representation::Ntt, Representation::NttShoup}) {
    std::vector<Poly> p_vec, q_vec;
    std::vector<std::reference_wrapper<const Poly>> p_refs, q_refs;

    for (int i = 0; i < 3; ++i) {
      p_vec.emplace_back(Poly::random(ctx_multi, repr, rng_));
      q_vec.emplace_back(Poly::random(ctx_multi, repr, rng_));
      p_refs.emplace_back(std::cref(p_vec.back()));
      q_refs.emplace_back(std::cref(q_vec.back()));
    }

    auto dot_result = dot_product(p_refs, q_refs);
    EXPECT_EQ(dot_result.representation(), repr);
    EXPECT_EQ(dot_result.ctx(), ctx_multi);
  }
}

/**
 * @brief Test variable time flag propagation in operations.
 */
TEST_F(PolyOpsTest, VariableTimePropagation) {
  auto ctx = Context::create(ArithmeticFixtureBasis(), 16);

  for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                    Representation::NttShoup}) {
    auto p = Poly::random(ctx, repr, rng_);
    auto q = Poly::random(ctx, repr, rng_);

    // Initially both should not allow variable time
    p.disallow_variable_time_computations();
    q.disallow_variable_time_computations();

    // Enable variable time for p
    p.allow_variable_time_computations();

    // Operations should propagate variable time flag
    auto r1 = p + q;  // Should allow variable time
    auto r2 = p - q;  // Should allow variable time
    auto r3 = -p;     // Should allow variable time

    if (repr != Representation::PowerBasis) {
      auto r4 = p * q;  // Should allow variable time
    }

    // Test scalar multiplication
    ::bfv::math::rns::BigUint scalar(42);
    auto r5 = p * scalar;  // Should allow variable time

    // Test in-place operations
    auto p_copy = p;
    p_copy += q;  // Should allow variable time

    auto q_copy = q;
    q_copy += p;  // Should allow variable time after operation
  }
}

/**
 * @brief Test representation compatibility checks.
 */
TEST_F(PolyOpsTest, RepresentationCompatibility) {
  auto ctx = Context::create(ArithmeticFixtureBasis(), 16);

  auto p_power = Poly::random(ctx, Representation::PowerBasis, rng_);
  auto p_ntt = Poly::random(ctx, Representation::Ntt, rng_);
  auto p_ntt_shoup = Poly::random(ctx, Representation::NttShoup, rng_);

  // Operations between different representations should fail
  EXPECT_THROW(p_power + p_ntt, DefaultException);
  EXPECT_THROW(p_power - p_ntt, DefaultException);
  EXPECT_THROW(p_ntt + p_ntt_shoup, DefaultException);
  EXPECT_THROW(p_ntt - p_ntt_shoup, DefaultException);
  EXPECT_THROW(p_power * p_ntt, DefaultException);
  EXPECT_THROW(p_ntt * p_ntt_shoup, DefaultException);

  // In-place operations should also fail
  EXPECT_THROW(p_power += p_ntt, DefaultException);
  EXPECT_THROW(p_power -= p_ntt, DefaultException);
  EXPECT_THROW(p_power *= p_ntt, DefaultException);
}

/**
 * @brief Test context compatibility checks.
 */
TEST_F(PolyOpsTest, ContextCompatibility) {
  auto ctx1 = Context::create({ArithmeticFixtureBasis()[0]}, 16);
  auto ctx2 = Context::create({ArithmeticFixtureBasis()[1]}, 16);

  auto p1 = Poly::random(ctx1, Representation::PowerBasis, rng_);
  auto p2 = Poly::random(ctx2, Representation::PowerBasis, rng_);

  // Operations between different contexts should fail
  EXPECT_THROW(p1 + p2, DefaultException);
  EXPECT_THROW(p1 - p2, DefaultException);
  EXPECT_THROW(p1 * p2, DefaultException);

  // In-place operations should also fail
  EXPECT_THROW(p1 += p2, DefaultException);
  EXPECT_THROW(p1 -= p2, DefaultException);
  EXPECT_THROW(p1 *= p2, DefaultException);
}

}  // namespace bfv::math::rq
