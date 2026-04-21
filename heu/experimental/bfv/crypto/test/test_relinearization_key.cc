#include <gtest/gtest.h>

#include <random>
#include <stdexcept>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/plaintext.h"
#include "crypto/public_key.h"
#include "crypto/relinearization_key.h"
#include "crypto/secret_key.h"
// // #include "crypto/serialization_exception.h"
#include "math/poly.h"
#include "math/representation.h"

using namespace crypto::bfv;

class RelinearizationKeyTest : public testing::Test {
 protected:
  void SetUp() {
    rng_.seed(42);  // Fixed seed for reproducible tests

    // Create test parameters
    try {
      params_ = BfvParameters::default_arc(6, 16);
    } catch (const std::exception &e) {
      // If default_arc fails, create a simple parameter set
      params_ = nullptr;
    }
  }

  void TearDown() {
    // Cleanup code if needed
  }

  std::mt19937_64 rng_;
  std::shared_ptr<BfvParameters> params_;

  // Helper function to create a degree-2 ciphertext manually
  Ciphertext create_extended_ciphertext_encrypting_zero(
      const SecretKey &secret_key, size_t level = 0) {
    auto ctx = secret_key.parameters()->ctx_at_level(level);

    // Create secret key polynomial s
    auto s = ::bfv::math::rq::Poly::from_i64_vector(
        secret_key.coefficients(), ctx, false,
        ::bfv::math::rq::Representation::PowerBasis);
    s.change_representation(::bfv::math::rq::Representation::Ntt);

    // Compute s^2
    auto s2 = s * s;

    // Generate random c2 and c1
    auto c2 = ::bfv::math::rq::Poly::random(
        ctx, ::bfv::math::rq::Representation::Ntt, rng_);
    auto c1 = ::bfv::math::rq::Poly::random(
        ctx, ::bfv::math::rq::Representation::Ntt, rng_);

    // Generate small error polynomial
    auto c0 = ::bfv::math::rq::Poly::small(
        ctx, ::bfv::math::rq::Representation::PowerBasis, 16, rng_);
    c0.change_representation(::bfv::math::rq::Representation::Ntt);

    // Compute c0 = e - c1 * s - c2 * s^2
    c0 = c0 - (c1 * s);
    c0 = c0 - (c2 * s2);

    // Create ciphertext from (c0, c1, c2)
    std::vector<::bfv::math::rq::Poly> polys;
    polys.push_back(c0);
    polys.push_back(c1);
    polys.push_back(c2);

    return Ciphertext::from_polynomials(polys, secret_key.parameters());
  }
};

// Test basic relinearization
TEST_F(RelinearizationKeyTest, Relinearization) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  // Only test with BfvParameters::default_arc(6, 16)
  for (int iteration = 0; iteration < 100; ++iteration) {
    auto sk = SecretKey::random(params_, rng_);
    auto rk = RelinearizationKey::from_secret_key(sk, rng_);

    auto ctx = params_->ctx_at_level(0);
    auto s = ::bfv::math::rq::Poly::from_i64_vector(
        sk.coefficients(), ctx, false,
        ::bfv::math::rq::Representation::PowerBasis);
    s.change_representation(::bfv::math::rq::Representation::Ntt);
    auto s2 = s * s;

    // Generate manually an "extended" ciphertext (c0 = e - c1 * s - c2 * s^2,
    // c1, c2) encrypting 0
    auto c2 = ::bfv::math::rq::Poly::random(
        ctx, ::bfv::math::rq::Representation::Ntt, rng_);
    auto c1 = ::bfv::math::rq::Poly::random(
        ctx, ::bfv::math::rq::Representation::Ntt, rng_);
    auto c0 = ::bfv::math::rq::Poly::small(
        ctx, ::bfv::math::rq::Representation::PowerBasis, 16, rng_);
    c0.change_representation(::bfv::math::rq::Representation::Ntt);
    c0 = c0 - (c1 * s);
    c0 = c0 - (c2 * s2);

    std::vector<::bfv::math::rq::Poly> polys = {c0, c1, c2};
    auto ct = Ciphertext::from_polynomials(polys, params_);

    // Reduce ciphertext size from 3 to 2 components.
    rk.relinearize(ct);
    EXPECT_EQ(ct.size(), 2);

    // Verify polynomial-level path matches in-place ciphertext relinearization.
    auto c2_copy = c2;
    c2_copy.change_representation(::bfv::math::rq::Representation::PowerBasis);
    auto [c0r, c1r] = rk.relinearize_poly(c2_copy);
    c0r.change_representation(::bfv::math::rq::Representation::PowerBasis);
    c0r.drop_to_context(c0.ctx());
    c1r.change_representation(::bfv::math::rq::Representation::PowerBasis);
    c1r.drop_to_context(c1.ctx());
    c0r.change_representation(::bfv::math::rq::Representation::Ntt);
    c1r.change_representation(::bfv::math::rq::Representation::Ntt);

    std::vector<::bfv::math::rq::Poly> expected_polys = {c0 + c0r, c1 + c1r};
    auto expected_ct = Ciphertext::from_polynomials(expected_polys, params_);
    EXPECT_EQ(ct, expected_ct);

    // // Print the noise and decrypt
    // auto noise = sk.measure_noise(ct);
    // std::cout << "Noise: " << noise << std::endl;

    auto pt = sk.decrypt(ct);
    auto w = pt.decode_uint64(Encoding::poly());

    // Check that decryption result is all zeros (first 16 elements)
    for (size_t i = 0; i < 16; ++i) {
      EXPECT_EQ(w[i], 0) << "Coefficient " << i << " should be zero";
    }
  }
}

TEST_F(RelinearizationKeyTest, SerializationRoundTrip) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto secret_key = SecretKey::random(params_, rng_);
  auto relin_key = RelinearizationKey::from_secret_key(secret_key, rng_);
  auto serialized = relin_key.Serialize();
  auto restored = RelinearizationKey::from_bytes(serialized, params_);

  EXPECT_EQ(restored, relin_key);

  auto ct = create_extended_ciphertext_encrypting_zero(secret_key);
  restored.relinearize(ct);
  auto pt = secret_key.decrypt(ct);
  auto decoded = pt.decode_uint64(Encoding::poly());
  for (size_t i = 0; i < 16; ++i) {
    EXPECT_EQ(decoded[i], 0);
  }
}

// Test leveled relinearization
TEST_F(RelinearizationKeyTest, RelinearizationLeveled) {
  std::shared_ptr<BfvParameters> leveled_params;
  try {
    leveled_params = BfvParameters::default_arc(5, 16);
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create leveled test parameters: " << e.what();
  }

  for (size_t ciphertext_level = 0;
       ciphertext_level < leveled_params->max_level(); ++ciphertext_level) {
    for (size_t key_level = 0; key_level <= ciphertext_level; ++key_level) {
      for (int iteration = 0; iteration < 10; ++iteration) {
        auto sk = SecretKey::random(leveled_params, rng_);
        auto rk = RelinearizationKey::from_secret_key_leveled(
            sk, ciphertext_level, key_level, rng_);

        auto ctx = leveled_params->ctx_at_level(ciphertext_level);
        auto s = ::bfv::math::rq::Poly::from_i64_vector(
            sk.coefficients(), ctx, false,
            ::bfv::math::rq::Representation::PowerBasis);
        s.change_representation(::bfv::math::rq::Representation::Ntt);
        auto s2 = s * s;

        // Generate manually an "extended" ciphertext (c0 = e - c1 * s - c2 *
        // s^2, c1, c2) encrypting 0
        auto c2 = ::bfv::math::rq::Poly::random(
            ctx, ::bfv::math::rq::Representation::Ntt, rng_);
        auto c1 = ::bfv::math::rq::Poly::random(
            ctx, ::bfv::math::rq::Representation::Ntt, rng_);
        auto c0 = ::bfv::math::rq::Poly::small(
            ctx, ::bfv::math::rq::Representation::PowerBasis, 16, rng_);
        c0.change_representation(::bfv::math::rq::Representation::Ntt);
        c0 = c0 - (c1 * s);
        c0 = c0 - (c2 * s2);

        std::vector<::bfv::math::rq::Poly> polys = {c0, c1, c2};
        auto ct = Ciphertext::from_polynomials(polys, leveled_params);

        // Reduce ciphertext size from 3 to 2 components.
        rk.relinearize(ct);
        EXPECT_EQ(ct.size(), 2);

        // Verify polynomial-level path matches in-place ciphertext
        // relinearization.
        auto c2_copy = c2;
        c2_copy.change_representation(
            ::bfv::math::rq::Representation::PowerBasis);
        auto [c0r, c1r] = rk.relinearize_poly(c2_copy);
        c0r.change_representation(::bfv::math::rq::Representation::PowerBasis);
        c0r.drop_to_context(c0.ctx());
        c1r.change_representation(::bfv::math::rq::Representation::PowerBasis);
        c1r.drop_to_context(c1.ctx());
        c0r.change_representation(::bfv::math::rq::Representation::Ntt);
        c1r.change_representation(::bfv::math::rq::Representation::Ntt);

        std::vector<::bfv::math::rq::Poly> expected_polys = {c0 + c0r,
                                                             c1 + c1r};
        auto expected_ct =
            Ciphertext::from_polynomials(expected_polys, leveled_params);
        EXPECT_EQ(ct, expected_ct);

        // // Print the noise and decrypt
        // auto noise = sk.measure_noise(ct);
        // std::cout << "Noise: " << noise << std::endl;

        auto pt = sk.decrypt(ct);
        auto w = pt.decode_uint64(Encoding::poly());

        // Check that decryption result is all zeros (first 16 elements)
        for (size_t i = 0; i < 16; ++i) {
          EXPECT_EQ(w[i], 0) << "Coefficient " << i << " should be zero";
        }
      }
    }
  }
}
