#include <gtest/gtest.h>

#include <memory>
#include <random>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/multiplicator.h"
#include "crypto/plaintext.h"
#include "crypto/relinearization_key.h"
#include "crypto/secret_key.h"
#include "math/primes.h"

using namespace crypto::bfv;

class MultiplicatorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Use fixed seed for reproducible tests
    rng.seed(42);
  }

  std::mt19937_64 rng;
};

TEST_F(MultiplicatorTest, Mul) {
  auto params = BfvParameters::default_arc(3, 16);

  for (int iter = 0; iter < 30; ++iter) {
    auto values = params->plaintext_random_vec(params->degree(), rng);

    // Calculate expected result: element-wise multiplication (values * values)
    std::vector<uint64_t> expected = values;
    auto plaintext_mod = params->plaintext_modulus();
    for (size_t i = 0; i < expected.size(); ++i) {
      expected[i] = (expected[i] * values[i]) % plaintext_mod;
    }

    // Create secret key and relinearization key
    auto secret_key = SecretKey::random(params, rng);
    auto relinearization_key =
        RelinearizationKey::from_secret_key(secret_key, rng);

    // Encode using SIMD encoding
    auto pt = Plaintext::encode(values, Encoding::simd(), params);
    auto ct1 = secret_key.encrypt(pt, rng);
    auto ct2 = secret_key.encrypt(pt, rng);

    // Test without mod switching
    auto multiplicator = Multiplicator::create_default(relinearization_key);
    auto ct3 = multiplicator->multiply(ct1, ct2);

    // // Measure noise (unsafe operation)
    // std::cout << "Noise: " << secret_key.measure_noise(ct3) << std::endl;

    auto result_pt = secret_key.decrypt(ct3);
    auto result_values = result_pt.decode_uint64(Encoding::simd());

    ASSERT_EQ(result_values.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
      EXPECT_EQ(result_values[i], expected[i])
          << "Mismatch at index " << i << " in iteration " << iter;
    }

    // Test with mod switching
    multiplicator->enable_mod_switching();
    auto ct3_mod_switch = multiplicator->multiply(ct1, ct2);
    EXPECT_EQ(ct3_mod_switch.level(), 1);

    // std::cout << "Noise: " << secret_key.measure_noise(ct3_mod_switch)
    //           << std::endl;

    auto result_pt_mod_switch = secret_key.decrypt(ct3_mod_switch);
    auto result_values_mod_switch =
        result_pt_mod_switch.decode_uint64(Encoding::simd());

    ASSERT_EQ(result_values_mod_switch.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
      EXPECT_EQ(result_values_mod_switch[i], expected[i])
          << "Mismatch at index " << i << " in iteration " << iter
          << " with mod switching";
    }
  }
}

TEST_F(MultiplicatorTest, MulAtLevel) {
  auto params = BfvParameters::default_arc(3, 16);

  for (int iter = 0; iter < 15; ++iter) {
    for (size_t level = 0; level < 2; ++level) {
      // Generate random values
      auto values = params->plaintext_random_vec(params->degree(), rng);

      // Calculate expected result: element-wise multiplication
      std::vector<uint64_t> expected = values;
      auto plaintext_mod = params->plaintext_modulus();
      for (size_t i = 0; i < expected.size(); ++i) {
        expected[i] = (expected[i] * values[i]) % plaintext_mod;
      }

      // Create secret key and leveled relinearization key
      auto secret_key = SecretKey::random(params, rng);
      auto relinearization_key = RelinearizationKey::from_secret_key_leveled(
          secret_key, level, level, rng);

      // Encode using SIMD encoding at specific level
      auto pt =
          Plaintext::encode(values, Encoding::simd_at_level(level), params);
      auto ct1 = secret_key.encrypt(pt, rng);
      auto ct2 = secret_key.encrypt(pt, rng);

      EXPECT_EQ(ct1.level(), level);
      EXPECT_EQ(ct2.level(), level);

      // Test without mod switching
      auto multiplicator = Multiplicator::create_default(relinearization_key);
      auto ct3 = multiplicator->multiply(ct1, ct2);

      // std::cout << "Noise: " << secret_key.measure_noise(ct3) << std::endl;

      auto result_pt = secret_key.decrypt(ct3);
      auto result_values = result_pt.decode_uint64(Encoding::simd());

      ASSERT_EQ(result_values.size(), expected.size());
      for (size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(result_values[i], expected[i])
            << "Mismatch at index " << i << " in iteration " << iter
            << " at level " << level;
      }

      // Test with mod switching
      multiplicator->enable_mod_switching();
      auto ct3_mod_switch = multiplicator->multiply(ct1, ct2);
      EXPECT_EQ(ct3_mod_switch.level(), level + 1);

      // std::cout << "Noise: " << secret_key.measure_noise(ct3_mod_switch)
      //           << std::endl;

      auto result_pt_mod_switch = secret_key.decrypt(ct3_mod_switch);
      auto result_values_mod_switch =
          result_pt_mod_switch.decode_uint64(Encoding::simd());

      ASSERT_EQ(result_values_mod_switch.size(), expected.size());
      for (size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(result_values_mod_switch[i], expected[i])
            << "Mismatch at index " << i << " in iteration " << iter
            << " at level " << level << " with mod switching";
      }
    }
  }
}

TEST_F(MultiplicatorTest, MulNoRelin) {
  auto params = BfvParameters::default_arc(2, 16);

  for (int iter = 0; iter < 10; ++iter) {
    // Generate random values
    auto values = params->plaintext_random_vec(params->degree(), rng);

    // Calculate expected result: element-wise multiplication
    std::vector<uint64_t> expected = values;
    auto plaintext_mod = params->plaintext_modulus();
    for (size_t i = 0; i < expected.size(); ++i) {
      expected[i] = (expected[i] * values[i]) % plaintext_mod;
    }

    // Create secret key and relinearization key
    auto secret_key = SecretKey::random(params, rng);
    auto relinearization_key =
        RelinearizationKey::from_secret_key(secret_key, rng);

    // Encode using SIMD encoding
    auto pt = Plaintext::encode(values, Encoding::simd(), params);
    auto ct1 = secret_key.encrypt(pt, rng);
    auto ct2 = secret_key.encrypt(pt, rng);

    // Create multiplicator without relinearization (simulate multiplicator.rk =
    // None) We need to create a custom multiplicator without relinearization
    // key
    auto one_factor = ::bfv::math::rns::ScalingFactor::one();
    auto ctx = params->ctx_at_level(0);
    auto post_mul_factor = ::bfv::math::rns::ScalingFactor(
        ::bfv::math::rns::BigUint(params->plaintext_modulus()),
        ::bfv::math::rns::BigUint(ctx->modulus()));

    size_t modulus_size = 0;
    auto moduli_sizes = params->moduli_sizes();
    for (size_t i = 0; i < ctx->moduli().size(); ++i) {
      modulus_size += moduli_sizes[i];
    }
    size_t n_moduli = (modulus_size + 60 + 62 - 1) / 62;

    std::vector<uint64_t> extended_basis = ctx->moduli();
    extended_basis.reserve(ctx->moduli().size() + n_moduli);
    uint64_t upper_bound = 1ULL << 62;
    while (extended_basis.size() < ctx->moduli().size() + n_moduli) {
      auto prime_opt = ::bfv::math::zq::generate_prime(62, 2 * params->degree(),
                                                       upper_bound);
      if (prime_opt.has_value()) {
        upper_bound = prime_opt.value();
        bool found = false;
        for (uint64_t existing : extended_basis) {
          if (existing == upper_bound) {
            found = true;
            break;
          }
        }
        if (!found) {
          extended_basis.push_back(upper_bound);
        }
      }
    }

    auto multiplicator = Multiplicator::create(
        one_factor, one_factor, extended_basis, post_mul_factor, params);

    EXPECT_FALSE(multiplicator->has_relinearization());

    // Test without mod switching
    auto ct3 = multiplicator->multiply(ct1, ct2);
    EXPECT_EQ(ct3.size(), 3);  // Should not be relinearized

    // std::cout << "Noise: " << secret_key.measure_noise(ct3) << std::endl;

    auto result_pt = secret_key.decrypt(ct3);
    auto result_values = result_pt.decode_uint64(Encoding::simd());

    ASSERT_EQ(result_values.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
      EXPECT_EQ(result_values[i], expected[i])
          << "Mismatch at index " << i << " in iteration " << iter;
    }

    // Test with mod switching
    multiplicator->enable_mod_switching();
    auto ct3_mod_switch = multiplicator->multiply(ct1, ct2);
    EXPECT_EQ(ct3_mod_switch.level(), 1);

    // std::cout << "Noise: " << secret_key.measure_noise(ct3_mod_switch)
    //           << std::endl;

    auto result_pt_mod_switch = secret_key.decrypt(ct3_mod_switch);
    auto result_values_mod_switch =
        result_pt_mod_switch.decode_uint64(Encoding::simd());

    ASSERT_EQ(result_values_mod_switch.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
      EXPECT_EQ(result_values_mod_switch[i], expected[i])
          << "Mismatch at index " << i << " in iteration " << iter
          << " with mod switching";
    }
  }
}

TEST_F(MultiplicatorTest, DifferentMulStrategy) {
  // Implement the second multiplication strategy from
  // https://eprint.iacr.org/2021/204
  auto params = BfvParameters::default_arc(3, 16);

  std::vector<uint64_t> extended_basis = params->moduli();

  // Add 3 additional primes
  auto prime1 = ::bfv::math::zq::generate_prime(62, 2 * params->degree(),
                                                extended_basis[2]);
  ASSERT_TRUE(prime1.has_value());
  extended_basis.push_back(prime1.value());

  auto prime2 = ::bfv::math::zq::generate_prime(62, 2 * params->degree(),
                                                extended_basis[3]);
  ASSERT_TRUE(prime2.has_value());
  extended_basis.push_back(prime2.value());

  auto prime3 = ::bfv::math::zq::generate_prime(62, 2 * params->degree(),
                                                extended_basis[4]);
  ASSERT_TRUE(prime3.has_value());
  extended_basis.push_back(prime3.value());

  // Create RNS context for the additional primes (extended_basis[3..])
  std::vector<uint64_t> rns_moduli(extended_basis.begin() + 3,
                                   extended_basis.end());
  auto rns_ctx =
      ::bfv::math::rq::Context::create_arc(rns_moduli, params->degree());

  for (int iter = 0; iter < 30; ++iter) {
    // Generate random values
    auto values = params->plaintext_random_vec(params->degree(), rng);

    // Calculate expected result: element-wise multiplication
    std::vector<uint64_t> expected = values;
    auto plaintext_mod = params->plaintext_modulus();
    for (size_t i = 0; i < expected.size(); ++i) {
      expected[i] = (expected[i] * values[i]) % plaintext_mod;
    }

    // Create secret key
    auto secret_key = SecretKey::random(params, rng);

    // Encode using SIMD encoding
    auto pt = Plaintext::encode(values, Encoding::simd(), params);
    auto ct1 = secret_key.encrypt(pt, rng);
    auto ct2 = secret_key.encrypt(pt, rng);

    // Create multiplicator with custom scaling factors
    auto lhs_scaling_factor = ::bfv::math::rns::ScalingFactor::one();
    auto rhs_scaling_factor = ::bfv::math::rns::ScalingFactor(
        ::bfv::math::rns::BigUint(rns_ctx->modulus()),
        ::bfv::math::rns::BigUint(params->ctx_at_level(0)->modulus()));
    auto post_mul_scaling_factor = ::bfv::math::rns::ScalingFactor(
        ::bfv::math::rns::BigUint(params->plaintext_modulus()),
        ::bfv::math::rns::BigUint(rns_ctx->modulus()));

    auto multiplicator =
        Multiplicator::create(lhs_scaling_factor, rhs_scaling_factor,
                              extended_basis, post_mul_scaling_factor, params);

    // Test without mod switching
    auto ct3 = multiplicator->multiply(ct1, ct2);

    // std::cout << "Noise: " << secret_key.measure_noise(ct3) << std::endl;

    auto result_pt = secret_key.decrypt(ct3);
    auto result_values = result_pt.decode_uint64(Encoding::simd());

    ASSERT_EQ(result_values.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
      EXPECT_EQ(result_values[i], expected[i])
          << "Mismatch at index " << i << " in iteration " << iter;
    }

    // Test with mod switching
    multiplicator->enable_mod_switching();
    auto ct3_mod_switch = multiplicator->multiply(ct1, ct2);
    EXPECT_EQ(ct3_mod_switch.level(), 1);

    // std::cout << "Noise: " << secret_key.measure_noise(ct3_mod_switch)
    //           << std::endl;

    auto result_pt_mod_switch = secret_key.decrypt(ct3_mod_switch);
    auto result_values_mod_switch =
        result_pt_mod_switch.decode_uint64(Encoding::simd());

    ASSERT_EQ(result_values_mod_switch.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
      EXPECT_EQ(result_values_mod_switch[i], expected[i])
          << "Mismatch at index " << i << " in iteration " << iter
          << " with mod switching";
    }
  }
}
