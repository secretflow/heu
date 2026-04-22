#include <gtest/gtest.h>

#include <iomanip>
#include <random>
#include <sstream>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/galois_key.h"
#include "crypto/plaintext.h"
#include "crypto/public_key.h"
#include "crypto/secret_key.h"
#include "math/biguint.h"

using namespace crypto::bfv;

class GaloisKeyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    rng_.seed(42);  // Fixed seed for reproducible tests
  }

  void TearDown() override {
    // Cleanup code if needed
  }

  std::mt19937_64 rng_;

  // Helper function to generate random values
  std::vector<uint64_t> generate_random_values(size_t count,
                                               uint64_t max_val = 1152) {
    std::vector<uint64_t> values(count);
    std::uniform_int_distribution<uint64_t> dist(0, max_val);
    for (size_t i = 0; i < count; ++i) {
      values[i] = dist(rng_);
    }
    return values;
  }
};

// Test relinearization
TEST_F(GaloisKeyTest, Relinearization) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    test_params.push_back(BfvParameters::default_arc(6, 16));
    test_params.push_back(BfvParameters::default_arc(3, 16));
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    for (int test_iter = 0; test_iter < 30; ++test_iter) {
      auto sk = SecretKey::random(params, rng_);
      auto v = params->plaintext_random_vec(params->degree(), rng_);
      size_t row_size = params->degree() >> 1;

      auto pt = Plaintext::encode(v, Encoding::simd(), params);
      auto ct = sk.encrypt(pt, rng_);

      for (size_t i = 1; i < 2 * params->degree(); ++i) {
        if ((i & 1) == 0) {
          // Even exponents should fail
          EXPECT_THROW(GaloisKey::create(sk, i, 0, 0, rng_),
                       ParameterException);
        } else {
          // Odd exponents should succeed
          auto gk = GaloisKey::create(sk, i, 0, 0, rng_);
          auto ct2 = gk.apply(ct);

          if (i == 3) {
            // Test column rotation by 1 (left rotation)
            auto pt_result = sk.decrypt(ct2);
            auto decoded_values = pt_result.decode_uint64(Encoding::simd());

            // Build expected output for left rotation by one within each row.
            std::vector<uint64_t> expected(params->degree(), 0);
            for (size_t j = 0; j < row_size - 1; ++j) {
              expected[j] = v[1 + j];
            }
            expected[row_size - 1] = v[0];
            for (size_t j = 0; j < row_size - 1; ++j) {
              expected[row_size + j] = v[row_size + 1 + j];
            }
            expected[2 * row_size - 1] = v[row_size];

            EXPECT_EQ(decoded_values, expected)
                << "Column rotation test failed for i=3";
          } else if (i == params->degree() * 2 - 1) {
            // Test row rotation (row swap)
            auto pt_result = sk.decrypt(ct2);
            auto decoded_values = pt_result.decode_uint64(Encoding::simd());

            // Build expected output after swapping the two rows.
            std::vector<uint64_t> expected(params->degree(), 0);
            for (size_t j = 0; j < row_size; ++j) {
              expected[j] = v[row_size + j];
            }
            for (size_t j = 0; j < row_size; ++j) {
              expected[row_size + j] = v[j];
            }

            EXPECT_EQ(decoded_values, expected)
                << "Row swap test failed for i=" << (params->degree() * 2 - 1);
          }
        }
      }
    }
  }
}

TEST_F(GaloisKeyTest, ProtoConversion) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    test_params.push_back(BfvParameters::default_arc(6, 16));
    test_params.push_back(BfvParameters::default_arc(4, 16));
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    auto sk = SecretKey::random(params, rng_);
    auto gk = GaloisKey::create(sk, 9, 0, 0, rng_);
    auto serialized = gk.Serialize();
    auto restored = GaloisKey::from_bytes(serialized, params);

    EXPECT_EQ(gk.exponent(), 9);
    EXPECT_EQ(gk.parameters(), params);
    EXPECT_FALSE(gk.empty());
    EXPECT_EQ(restored, gk);

    auto values = params->plaintext_random_vec(params->degree(), rng_);
    auto pt = Plaintext::encode(values, Encoding::simd(), params);
    auto ct = sk.encrypt(pt, rng_);
    auto result = sk.decrypt(restored.apply(ct), Encoding::simd());
    EXPECT_FALSE(result.empty());
  }
}
