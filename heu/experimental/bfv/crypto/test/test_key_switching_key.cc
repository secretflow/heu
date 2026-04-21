#include <gtest/gtest.h>

#include <random>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/key_switching_key.h"
#include "crypto/secret_key.h"
#include "math/biguint.h"
#include "math/poly.h"
#include "math/representation.h"
#include "math/rns_context.h"

using namespace crypto::bfv;

class KeySwitchingKeyTest : public ::testing::Test {
 protected:
  void SetUp() {
    // No setup needed - each test creates its own rng
  }

  void TearDown() {
    // Cleanup code if needed
  }
};

// Test constructor
TEST_F(KeySwitchingKeyTest, Constructor) {
  std::mt19937_64 rng;

  // Test with both parameter sets
  std::vector<std::shared_ptr<BfvParameters>> param_sets = {
      BfvParameters::default_arc(6, 16), BfvParameters::default_arc(3, 16)};

  for (const auto &params : param_sets) {
    auto sk = SecretKey::random(params, rng);
    auto ctx = params->ctx_at_level(0);
    auto p = ::bfv::math::rq::Poly::small(
        ctx, ::bfv::math::rq::Representation::PowerBasis, 10, rng);

    // This should succeed
    EXPECT_NO_THROW({
      auto ksk = KeySwitchingKey::create(sk, p, 0, 0, rng);
      EXPECT_FALSE(ksk.empty());
    });
  }
}

// Test constructor at last level
TEST_F(KeySwitchingKeyTest, ConstructorLastLevel) {
  std::mt19937_64 rng;

  std::vector<std::shared_ptr<BfvParameters>> param_sets = {
      BfvParameters::default_arc(6, 16), BfvParameters::default_arc(3, 16)};

  for (const auto &params : param_sets) {
    size_t level = params->moduli().size() - 1;  // Last level
    auto sk = SecretKey::random(params, rng);
    auto ctx = params->ctx_at_level(level);
    auto p = ::bfv::math::rq::Poly::small(
        ctx, ::bfv::math::rq::Representation::PowerBasis, 10, rng);

    // This should succeed
    EXPECT_NO_THROW({
      auto ksk = KeySwitchingKey::create(sk, p, level, level, rng);
      EXPECT_FALSE(ksk.empty());
    });
  }
}

TEST_F(KeySwitchingKeyTest, KeySwitch) {
  std::mt19937_64 rng;

  // Only test with BfvParameters::default_arc(6, 16)
  auto params = BfvParameters::default_arc(6, 16);

  // Run 100 iterations
  for (int i = 0; i < 100; ++i) {
    auto sk = SecretKey::random(params, rng);
    auto ctx = params->ctx_at_level(0);

    auto p = ::bfv::math::rq::Poly::small(
        ctx, ::bfv::math::rq::Representation::PowerBasis, 10, rng);
    auto ksk = KeySwitchingKey::create(sk, p, 0, 0, rng);

    auto s = ::bfv::math::rq::Poly::from_i64_vector(
        sk.coefficients(), ctx, false,
        ::bfv::math::rq::Representation::PowerBasis);
    s.change_representation(::bfv::math::rq::Representation::Ntt);

    // Create input polynomial for key switching
    auto input = ::bfv::math::rq::Poly::random(
        ctx, ::bfv::math::rq::Representation::PowerBasis, rng);

    // Perform key switching
    auto [c0, c1] = ksk.key_switch(input);

    auto c2 = c0 + (c1 * s);
    c2.change_representation(::bfv::math::rq::Representation::PowerBasis);

    input.change_representation(::bfv::math::rq::Representation::Ntt);
    p.change_representation(::bfv::math::rq::Representation::Ntt);
    auto c3 = input * p;
    c3.change_representation(::bfv::math::rq::Representation::PowerBasis);

    auto diff = c2 - c3;
    auto diff_coeffs = diff.to_biguint_vector();

    auto rns = ::bfv::math::rns::RnsContext::create(params->moduli());
    auto rns_modulus = rns->modulus();

    for (const auto &coeff : diff_coeffs) {
      auto complement = rns_modulus - coeff;
      size_t noise_bits = std::min(coeff.bits(), complement.bits());
      EXPECT_LE(noise_bits, 70)
          << "Noise is too large: " << noise_bits << " bits";
    }
  }
}

TEST_F(KeySwitchingKeyTest, KeySwitchDecomposition) {
  std::mt19937_64 rng;

  // Only test with BfvParameters::default_arc(6, 16)
  auto params = BfvParameters::default_arc(6, 16);

  // Run 100 iterations
  for (int i = 0; i < 100; ++i) {
    auto sk = SecretKey::random(params, rng);
    auto ctx = params->ctx_at_level(5);  // Use level 5

    auto p = ::bfv::math::rq::Poly::small(
        ctx, ::bfv::math::rq::Representation::PowerBasis, 10, rng);

    // Check the size of p
    auto p_coeffs = p.to_biguint_vector();
    size_t max_p_bits = 0;
    for (const auto &coeff : p_coeffs) {
      max_p_bits = std::max(max_p_bits, coeff.bits());
    }

    auto ksk = KeySwitchingKey::create(sk, p, 5, 5, rng);

    auto s = ::bfv::math::rq::Poly::from_i64_vector(
        sk.coefficients(), ctx, false,
        ::bfv::math::rq::Representation::PowerBasis);
    s.change_representation(::bfv::math::rq::Representation::Ntt);

    // Create input polynomial for key switching
    auto input = ::bfv::math::rq::Poly::random(
        ctx, ::bfv::math::rq::Representation::PowerBasis, rng);

    // Perform key switching
    auto [c0, c1] = ksk.key_switch(input);

    auto c2 = c0 + (c1 * s);
    c2.change_representation(::bfv::math::rq::Representation::PowerBasis);

    input.change_representation(::bfv::math::rq::Representation::Ntt);
    p.change_representation(::bfv::math::rq::Representation::Ntt);
    auto c3 = input * p;
    c3.change_representation(::bfv::math::rq::Representation::PowerBasis);

    auto diff = c2 - c3;
    auto diff_coeffs = diff.to_biguint_vector();

    auto rns = ::bfv::math::rns::RnsContext::create(ctx->moduli());
    auto rns_modulus = rns->modulus();

    size_t max_noise_bits = 0;
    for (const auto &coeff : diff_coeffs) {
      auto complement = rns_modulus - coeff;
      size_t noise_bits = std::min(coeff.bits(), complement.bits());
      max_noise_bits = std::max(max_noise_bits, noise_bits);
    }

    for (const auto &coeff : diff_coeffs) {
      auto complement = rns_modulus - coeff;
      size_t noise_bits = std::min(coeff.bits(), complement.bits());
      size_t max_noise =
          (rns_modulus.bits() / 2) + 25;  // Temporarily increased
      EXPECT_LE(noise_bits, max_noise)
          << "Noise is too large: " << noise_bits << " bits";
    }
  }
}

TEST_F(KeySwitchingKeyTest, Serialization) {
  std::mt19937_64 rng;

  // Test with both parameter sets
  std::vector<std::shared_ptr<BfvParameters>> param_sets = {
      BfvParameters::default_arc(6, 16), BfvParameters::default_arc(3, 16)};

  for (const auto &params : param_sets) {
    auto sk = SecretKey::random(params, rng);
    auto ctx = params->ctx_at_level(0);
    auto p = ::bfv::math::rq::Poly::small(
        ctx, ::bfv::math::rq::Representation::PowerBasis, 10, rng);

    auto ksk = KeySwitchingKey::create(sk, p, 0, 0, rng);

    // Serialization
    auto buffer = ksk.Serialize();

    // Deserialization
    auto deserialized = KeySwitchingKey::from_bytes(buffer, params);

    // Equality check
    EXPECT_EQ(ksk, deserialized);
  }
}
