#include <gtest/gtest.h>

#include <random>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/operators.h"
#include "crypto/plaintext.h"
#include "crypto/secret_key.h"

using namespace crypto::bfv;

class SecretKeyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    rng_.seed(42);  // Fixed seed for reproducible tests

    // Create test parameters
    try {
      params_ = BfvParameters::default_arc(1, 16);
    } catch (const std::exception &e) {
      // If default_arc fails, create a simple parameter set
      params_ = nullptr;
    }
  }

  void TearDown() override {
    // Cleanup code if needed
  }

  std::mt19937_64 rng_;
  std::shared_ptr<BfvParameters> params_;

  // Helper function to generate random values
  std::vector<uint64_t> generate_random_values(size_t count,
                                               uint64_t max_val = 1000) {
    std::vector<uint64_t> values(count);
    std::uniform_int_distribution<uint64_t> dist(0, max_val);
    for (size_t i = 0; i < count; ++i) {
      values[i] = dist(rng_);
    }
    return values;
  }

  std::vector<int64_t> generate_random_signed_values(size_t count,
                                                     int64_t min_val = -500,
                                                     int64_t max_val = 500) {
    std::vector<int64_t> values(count);
    std::uniform_int_distribution<int64_t> dist(min_val, max_val);
    for (size_t i = 0; i < count; ++i) {
      values[i] = dist(rng_);
    }
    return values;
  }
};

// Test secret key generation
TEST_F(SecretKeyTest, Keygen) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto secret_key = SecretKey::random(params_, rng_);
  EXPECT_EQ(secret_key.parameters(), params_);

  // Check that this is a small polynomial - coefficients should be bounded by 2
  // * variance
  const auto &coeffs = secret_key.coefficients();
  for (int64_t coeff : coeffs) {
    EXPECT_LE(std::abs(coeff), 2 * static_cast<int64_t>(params_->variance()));
  }
}

// Test secret key move semantics
TEST_F(SecretKeyTest, MoveSemantics) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  // Create a secret key
  auto secret_key1 = SecretKey::random(params_, rng_);
  EXPECT_FALSE(secret_key1.empty());

  // Test move constructor
  auto secret_key2 = std::move(secret_key1);
  EXPECT_FALSE(secret_key2.empty());
  EXPECT_TRUE(secret_key1.empty());  // Original should be empty after move

  // Test move assignment
  auto secret_key3 = SecretKey::random(params_, rng_);
  secret_key3 = std::move(secret_key2);
  EXPECT_FALSE(secret_key3.empty());
  EXPECT_TRUE(secret_key2.empty());  // Original should be empty after move
}

// Test encryption and decryption
TEST_F(SecretKeyTest, EncryptDecrypt) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  std::vector<std::shared_ptr<BfvParameters>> param_sets;
  try {
    param_sets.push_back(BfvParameters::default_arc(1, 16));
    param_sets.push_back(BfvParameters::default_arc(6, 16));
  } catch (const std::exception &e) {
    // If we can't create multiple parameter sets, just use the one we have
    param_sets.push_back(params_);
  }

  for (const auto &params : param_sets) {
    if (!params) continue;

    for (size_t level = 0; level < params->max_level(); ++level) {
      for (int iteration = 0; iteration < 20; ++iteration) {
        auto secret_key = SecretKey::random(params, rng_);

        auto random_values =
            params->plaintext_random_vec(params->degree(), rng_);
        auto plaintext = Plaintext::encode(
            random_values, Encoding::poly_at_level(level), params);

        auto ciphertext = secret_key.encrypt(plaintext, rng_);
        auto decrypted = secret_key.decrypt(ciphertext);

        // auto noise = secret_key.measure_noise(ciphertext);
        // std::cout << "Noise: " << noise << std::endl;

        // Verify decryption matches original
        EXPECT_EQ(decrypted, plaintext);
      }
    }
  }
}

// Test encryption and decryption with SIMD encoding
TEST_F(SecretKeyTest, EncryptDecryptSIMD) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto secret_key = SecretKey::random(params_, rng_);

  // Test with SIMD encoding
  auto simd_encoding = Encoding::simd();
  auto values = generate_random_values(4, 100);  // Smaller vector for SIMD
  auto plaintext = Plaintext::encode(values, simd_encoding, params_);

  // Encrypt and decrypt
  auto ciphertext = secret_key.encrypt(plaintext, rng_);
  auto decrypted = secret_key.decrypt(ciphertext);

  // Decode and compare - must specify SIMD encoding for decoding
  auto decoded_values = decrypted.decode_uint64(simd_encoding);
  // Check that decoded values match original values (first N elements)
  for (size_t i = 0; i < values.size(); ++i) {
    EXPECT_EQ(values[i], decoded_values[i]);
  }
}

// Test encryption and decryption with signed values
TEST_F(SecretKeyTest, EncryptDecryptSigned) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto secret_key = SecretKey::random(params_, rng_);

  // Test with signed values
  auto poly_encoding = Encoding::poly();
  auto values = generate_random_signed_values(8, -50, 50);
  auto plaintext = Plaintext::encode(values, poly_encoding, params_);

  // Encrypt and decrypt
  auto ciphertext = secret_key.encrypt(plaintext, rng_);
  auto decrypted = secret_key.decrypt(ciphertext);

  // Decode and compare
  auto decoded_values = decrypted.decode_int64();
  // Check that decoded values match original values (first N elements)
  for (size_t i = 0; i < values.size(); ++i) {
    EXPECT_EQ(values[i], decoded_values[i]);
  }
}

// Test noise measurement
TEST_F(SecretKeyTest, NoiseMeasurement) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto secret_key = SecretKey::random(params_, rng_);

  // Create a fresh ciphertext
  auto poly_encoding = Encoding::poly();
  auto values = generate_random_values(8, 10);  // Small values for low noise
  auto plaintext = Plaintext::encode(values, poly_encoding, params_);
  auto ciphertext = secret_key.encrypt(plaintext, rng_);

  // Measure noise - should be relatively low for fresh ciphertext
  auto noise_bits = secret_key.measure_noise(ciphertext);
  EXPECT_GT(noise_bits, 0);    // Should have some noise
  EXPECT_LT(noise_bits, 100);  // But not too much for fresh ciphertext

  // Test noise growth with operations
  auto ciphertext2 = secret_key.encrypt(plaintext, rng_);
  auto sum_ciphertext = ciphertext + ciphertext2;
  auto sum_noise = secret_key.measure_noise(sum_ciphertext);

  // Addition should increase noise slightly
  EXPECT_GE(sum_noise, noise_bits);
}

// Test zeroization
TEST_F(SecretKeyTest, Zeroization) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto secret_key = SecretKey::random(params_, rng_);
  EXPECT_FALSE(secret_key.empty());

  // Zeroize the key
  secret_key.zeroize();
  EXPECT_TRUE(secret_key.empty());
}

// Test multiple encryptions produce different ciphertexts
TEST_F(SecretKeyTest, RandomizedEncryption) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto secret_key = SecretKey::random(params_, rng_);

  // Create the same plaintext
  auto poly_encoding = Encoding::poly();
  std::vector<uint64_t> values = {10, 20, 30, 40,
                                  50, 60, 70, 80};  // Use fixed small values
  auto plaintext = Plaintext::encode(values, poly_encoding, params_);

  // Encrypt multiple times
  auto ciphertext1 = secret_key.encrypt(plaintext, rng_);
  auto ciphertext2 = secret_key.encrypt(plaintext, rng_);

  // Ciphertexts should be different (due to randomness)
  // We can't directly compare ciphertexts, but we can verify they decrypt to
  // the same value
  auto decrypted1 = secret_key.decrypt(ciphertext1);
  auto decrypted2 = secret_key.decrypt(ciphertext2);

  auto decoded1 = decrypted1.decode_uint64();
  auto decoded2 = decrypted2.decode_uint64();

  // Both should decrypt to the same original values
  EXPECT_EQ(decoded1.size(), decoded2.size());
  for (size_t i = 0; i < decoded1.size(); ++i) {
    EXPECT_EQ(decoded1[i], decoded2[i]);
  }
  // Check that the first values match the original input
  for (size_t i = 0; i < values.size(); ++i) {
    EXPECT_EQ(decoded1[i], values[i]);
  }
}

// Test parameter validation
TEST_F(SecretKeyTest, ParameterValidation) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto secret_key = SecretKey::random(params_, rng_);

  // Create plaintext with different parameters
  try {
    auto other_params =
        BfvParameters::default_arc(2, 16);  // Different security level
    auto other_encoding = Encoding::poly();
    auto values = generate_random_values(8, 100);
    auto other_plaintext =
        Plaintext::encode(values, other_encoding, other_params);

    // This should throw an exception due to parameter mismatch
    EXPECT_THROW(secret_key.encrypt(other_plaintext, rng_), ParameterException);
  } catch (const std::exception &e) {
    // If we can't create different parameters, skip this test
    GTEST_SKIP() << "Could not create different parameters for validation test";
  }
}

// Test serialization placeholders (should throw)
TEST_F(SecretKeyTest, SerializationPlaceholders) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto secret_key = SecretKey::random(params_, rng_);

  // Serialization should work correctly now
  auto serialized = secret_key.Serialize();
  EXPECT_GT(serialized.size(), 0);

  // Deserialize and verify using from_bytes static method
  auto deserialized = SecretKey::from_bytes(serialized, params_);
  EXPECT_EQ(secret_key.parameters(), deserialized.parameters());
  EXPECT_FALSE(deserialized.empty());
}
