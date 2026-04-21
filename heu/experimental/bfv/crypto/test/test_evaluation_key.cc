#include <gtest/gtest.h>

#include <iomanip>
#include <random>
#include <sstream>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/evaluation_key.h"
#include "crypto/plaintext.h"
#include "crypto/public_key.h"
#include "crypto/secret_key.h"
#include "math/biguint.h"

using namespace crypto::bfv;

class EvaluationKeyTest : public ::testing::Test {
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

TEST_F(EvaluationKeyTest, Builder) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    test_params.push_back(BfvParameters::default_arc(6, 16));
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    auto sk = SecretKey::random(params, rng_);
    size_t max_level = params->max_level();

    for (size_t ciphertext_level = 0; ciphertext_level <= max_level;
         ++ciphertext_level) {
      for (size_t evaluation_key_level = 0;
           evaluation_key_level <= std::min(max_level, ciphertext_level);
           ++evaluation_key_level) {
        auto builder = EvaluationKeyBuilder::create_leveled(
            sk, ciphertext_level, evaluation_key_level);

        EXPECT_FALSE(builder.build(rng_).supports_row_rotation());
        EXPECT_FALSE(builder.build(rng_).supports_column_rotation_by(0));
        EXPECT_FALSE(builder.build(rng_).supports_column_rotation_by(1));
        EXPECT_FALSE(builder.build(rng_).supports_inner_sum());
        EXPECT_FALSE(builder.build(rng_).supports_expansion(1));
        EXPECT_TRUE(builder.build(rng_).supports_expansion(0));

        EXPECT_THROW(builder.enable_column_rotation(0), std::exception);

        size_t max_expansion = 64 - __builtin_clzll(params->degree());
        EXPECT_THROW(builder.enable_expansion(max_expansion), std::exception);

        // Enable column rotation
        builder.enable_column_rotation(1);
        EXPECT_TRUE(builder.build(rng_).supports_column_rotation_by(1));
        EXPECT_FALSE(builder.build(rng_).supports_row_rotation());
        EXPECT_FALSE(builder.build(rng_).supports_inner_sum());
        EXPECT_FALSE(builder.build(rng_).supports_expansion(1));

        // Enable row rotation
        builder.enable_row_rotation();
        EXPECT_TRUE(builder.build(rng_).supports_row_rotation());
        EXPECT_FALSE(builder.build(rng_).supports_inner_sum());
        EXPECT_FALSE(builder.build(rng_).supports_expansion(1));

        // Enable inner sum
        builder.enable_inner_sum();
        EXPECT_TRUE(builder.build(rng_).supports_inner_sum());
        EXPECT_TRUE(builder.build(rng_).supports_expansion(1));
        EXPECT_FALSE(builder.build(rng_).supports_expansion(
            64 - 1 - __builtin_clzll(params->degree())));

        // Enable maximum expansion
        builder.enable_expansion(64 - 1 - __builtin_clzll(params->degree()));
        EXPECT_TRUE(builder.build(rng_).supports_expansion(
            64 - 1 - __builtin_clzll(params->degree())));

        // Final build should succeed
        EXPECT_NO_THROW(builder.build(rng_));

        // Test that enabling inner sum enables row rotation and column
        // rotations
        auto inner_sum_builder = EvaluationKeyBuilder::create_leveled(sk, 0, 0);
        inner_sum_builder.enable_inner_sum();
        auto ek = inner_sum_builder.build(rng_);
        EXPECT_TRUE(ek.supports_inner_sum());
        EXPECT_TRUE(ek.supports_row_rotation());

        size_t i = 1;
        while (i < params->degree() / 2) {
          EXPECT_TRUE(ek.supports_column_rotation_by(i));
          i *= 2;
        }
        EXPECT_FALSE(ek.supports_column_rotation_by(params->degree() / 2 - 1));
      }
    }

    // Test invalid level combinations
    EXPECT_THROW(EvaluationKeyBuilder::create_leveled(sk, 0, 1),
                 std::exception);
  }
}

TEST_F(EvaluationKeyTest, OperationEnablement) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    auto params_6 = BfvParameters::default_arc(6, 16);
    auto params_5 = BfvParameters::default_arc(5, 16);

    test_params.push_back(params_6);
    test_params.push_back(params_5);
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    auto sk = SecretKey::random(params, rng_);
    size_t max_level = params->max_level();

    for (size_t ciphertext_level = 0; ciphertext_level <= max_level;
         ++ciphertext_level) {
      for (size_t evaluation_key_level = 0;
           evaluation_key_level <= std::min(max_level, ciphertext_level);
           ++evaluation_key_level) {
        // Test initial state - no operations enabled
        {
          auto builder = EvaluationKeyBuilder::create_leveled(
              sk, ciphertext_level, evaluation_key_level);
          EXPECT_FALSE(builder.build(rng_).supports_row_rotation());
          EXPECT_FALSE(builder.build(rng_).supports_column_rotation_by(0));
          EXPECT_FALSE(builder.build(rng_).supports_column_rotation_by(1));
          EXPECT_FALSE(builder.build(rng_).supports_inner_sum());
          EXPECT_FALSE(builder.build(rng_).supports_expansion(1));
          EXPECT_TRUE(builder.build(rng_).supports_expansion(0));
        }

        // Enable column rotation
        {
          auto builder = EvaluationKeyBuilder::create_leveled(
              sk, ciphertext_level, evaluation_key_level);
          builder.enable_column_rotation(1);
          EXPECT_TRUE(builder.build(rng_).supports_column_rotation_by(1));
          EXPECT_FALSE(builder.build(rng_).supports_row_rotation());
          EXPECT_FALSE(builder.build(rng_).supports_inner_sum());
          EXPECT_FALSE(builder.build(rng_).supports_expansion(1));
        }

        // Enable row rotation
        {
          auto builder = EvaluationKeyBuilder::create_leveled(
              sk, ciphertext_level, evaluation_key_level);
          builder.enable_column_rotation(1);
          builder.enable_row_rotation();
          EXPECT_TRUE(builder.build(rng_).supports_row_rotation());
          EXPECT_FALSE(builder.build(rng_).supports_inner_sum());
          EXPECT_FALSE(builder.build(rng_).supports_expansion(1));
        }

        // Enable inner sum - this should also enable expansion(1)
        {
          auto builder = EvaluationKeyBuilder::create_leveled(
              sk, ciphertext_level, evaluation_key_level);
          builder.enable_column_rotation(1);
          builder.enable_row_rotation();
          builder.enable_inner_sum();
          EXPECT_TRUE(builder.build(rng_).supports_inner_sum());
          EXPECT_TRUE(builder.build(rng_).supports_expansion(1));

          // Calculate max expansion level
          size_t max_expansion_level =
              64 - 1 - __builtin_clzll(params->degree());
          EXPECT_FALSE(
              builder.build(rng_).supports_expansion(max_expansion_level));

          // Enable maximum expansion
          builder.enable_expansion(max_expansion_level);
          EXPECT_TRUE(
              builder.build(rng_).supports_expansion(max_expansion_level));
        }
      }
    }
  }
}

TEST_F(EvaluationKeyTest, KeyProperties) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    auto params_6 = BfvParameters::default_arc(6, 16);
    auto params_5 = BfvParameters::default_arc(5, 16);

    test_params.push_back(params_6);
    test_params.push_back(params_5);
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    auto sk = SecretKey::random(params, rng_);

    // Test regular builder
    auto builder = EvaluationKeyBuilder::create(sk);
    builder.enable_inner_sum();
    auto eval_key = builder.build(rng_);

    EXPECT_EQ(eval_key.parameters(), params);
    EXPECT_FALSE(eval_key.empty());

    // Test leveled builder
    size_t ciphertext_level = 2;
    size_t evaluation_key_level = 1;
    auto leveled_builder = EvaluationKeyBuilder::create_leveled(
        sk, ciphertext_level, evaluation_key_level);
    leveled_builder.enable_inner_sum();
    auto leveled_eval_key = leveled_builder.build(rng_);

    EXPECT_EQ(leveled_eval_key.ciphertext_level(), ciphertext_level);
    EXPECT_EQ(leveled_eval_key.evaluation_key_level(), evaluation_key_level);
    EXPECT_EQ(leveled_eval_key.parameters(), params);
    EXPECT_FALSE(leveled_eval_key.empty());
  }
}

TEST_F(EvaluationKeyTest, InnerSumOperation) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    auto params_6 = BfvParameters::default_arc(6, 16);
    auto params_5 = BfvParameters::default_arc(5, 16);

    test_params.push_back(params_6);
    test_params.push_back(params_5);
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    auto sk = SecretKey::random(params, rng_);
    auto builder = EvaluationKeyBuilder::create(sk);
    builder.enable_inner_sum();
    auto eval_key = builder.build(rng_);

    // Create test data
    auto v = generate_random_values(params->degree());
    auto pt = Plaintext::encode(v, Encoding::simd(), params);
    auto ct = sk.encrypt(pt, rng_);

    // Perform inner sum
    auto result_ct = eval_key.computes_inner_sum(ct);
    auto result_pt = sk.decrypt(result_ct, Encoding::simd());
    auto decoded_values = result_pt.decode_uint64(Encoding::simd());

    // Verify the result (inner sum should sum all elements)
    uint64_t expected_sum = 0;
    for (const auto &val : v) {
      expected_sum += val;
    }
    expected_sum %= params->plaintext_modulus();

    // All slots should contain the same sum value
    for (size_t i = 0; i < params->degree(); ++i) {
      EXPECT_EQ(decoded_values[i], expected_sum)
          << "Inner sum failed at position " << i;
    }
  }
}

TEST_F(EvaluationKeyTest, RowRotationOperation) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    auto params_6 = BfvParameters::default_arc(6, 16);
    auto params_5 = BfvParameters::default_arc(5, 16);

    test_params.push_back(params_6);
    test_params.push_back(params_5);
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    for (size_t test_iter = 0; test_iter < 50; ++test_iter) {
      for (size_t ciphertext_level = 0; ciphertext_level <= params->max_level();
           ++ciphertext_level) {
        for (size_t evaluation_key_level = 0;
             evaluation_key_level <=
             std::min(params->max_level() - 1, ciphertext_level);
             ++evaluation_key_level) {
          auto sk = SecretKey::random(params, rng_);
          auto builder = EvaluationKeyBuilder::create_leveled(
              sk, ciphertext_level, evaluation_key_level);
          builder.enable_row_rotation();
          auto eval_key = builder.build(rng_);

          auto v = generate_random_values(params->degree(),
                                          params->plaintext_modulus() - 1);

          size_t row_size = params->degree() >> 1;

          std::vector<uint64_t> expected(params->degree(), 0);
          for (size_t idx = 0; idx < row_size; ++idx) {
            expected[idx] = v[row_size + idx];
          }
          for (size_t idx = 0; idx < row_size; ++idx) {
            expected[row_size + idx] = v[idx];
          }

          auto pt = Plaintext::encode(
              v, Encoding::simd_at_level(ciphertext_level), params);
          auto ct = sk.encrypt(pt, rng_);

          auto result_ct = eval_key.rotates_rows(ct);
          auto result_pt =
              sk.decrypt(result_ct, Encoding::simd_at_level(ciphertext_level));
          auto decoded_values = result_pt.decode_uint64(
              Encoding::simd_at_level(ciphertext_level));

          EXPECT_EQ(decoded_values, expected) << "Row rotation failed";
        }
      }
    }
  }
}

TEST_F(EvaluationKeyTest, ColumnRotationOperation) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    auto params_6 = BfvParameters::default_arc(6, 16);
    auto params_5 = BfvParameters::default_arc(5, 16);

    test_params.push_back(params_6);
    test_params.push_back(params_5);
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    size_t row_size = params->degree() >> 1;

    for (size_t test_iter = 0; test_iter < 50; ++test_iter) {
      for (size_t i = 1; i < row_size; ++i) {
        for (size_t ciphertext_level = 0;
             ciphertext_level <= params->max_level(); ++ciphertext_level) {
          for (size_t evaluation_key_level = 0;
               evaluation_key_level <=
               std::min(params->max_level(), ciphertext_level);
               ++evaluation_key_level) {
            auto sk = SecretKey::random(params, rng_);
            auto builder = EvaluationKeyBuilder::create_leveled(
                sk, ciphertext_level, evaluation_key_level);
            builder.enable_column_rotation(i);
            auto eval_key = builder.build(rng_);

            auto v = generate_random_values(params->degree(),
                                            params->plaintext_modulus() - 1);

            std::vector<uint64_t> expected(params->degree(), 0);

            for (size_t idx = 0; idx < row_size - i; ++idx) {
              expected[idx] = v[i + idx];
            }

            for (size_t idx = 0; idx < i; ++idx) {
              expected[row_size - i + idx] = v[idx];
            }

            for (size_t idx = 0; idx < row_size - i; ++idx) {
              expected[row_size + idx] = v[row_size + i + idx];
            }

            for (size_t idx = 0; idx < i; ++idx) {
              expected[2 * row_size - i + idx] = v[row_size + idx];
            }

            auto pt = Plaintext::encode(
                v, Encoding::simd_at_level(ciphertext_level), params);
            auto ct = sk.encrypt(pt, rng_);

            auto result_ct = eval_key.rotates_columns_by(ct, i);
            auto result_pt = sk.decrypt(
                result_ct, Encoding::simd_at_level(ciphertext_level));
            auto decoded_values = result_pt.decode_uint64(
                Encoding::simd_at_level(ciphertext_level));

            EXPECT_EQ(decoded_values, expected)
                << "Column rotation by " << i << " failed";
          }
        }
      }
    }
  }
}

TEST_F(EvaluationKeyTest, ExpansionOperation) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    auto params_6 = BfvParameters::default_arc(6, 16);
    auto params_5 = BfvParameters::default_arc(5, 16);

    test_params.push_back(params_6);
    test_params.push_back(params_5);
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    size_t log_degree = 64 - 1 - __builtin_clzll(params->degree());

    for (size_t test_iter = 0; test_iter < 15; ++test_iter) {
      for (size_t i = 1; i < 1 + log_degree; ++i) {
        for (size_t ciphertext_level = 0;
             ciphertext_level <= params->max_level(); ++ciphertext_level) {
          for (size_t evaluation_key_level = 0;
               evaluation_key_level <=
               std::min(params->max_level(), ciphertext_level);
               ++evaluation_key_level) {
            auto sk = SecretKey::random(params, rng_);
            auto builder = EvaluationKeyBuilder::create_leveled(
                sk, ciphertext_level, evaluation_key_level);
            builder.enable_expansion(i);
            auto eval_key = builder.build(rng_);

            EXPECT_TRUE(eval_key.supports_expansion(i));
            EXPECT_FALSE(eval_key.supports_expansion(i + 1));

            size_t expansion_size = 1 << i;
            auto v = generate_random_values(expansion_size,
                                            params->plaintext_modulus() - 1);

            auto pt = Plaintext::encode(
                v, Encoding::poly_at_level(ciphertext_level), params);
            auto ct = sk.encrypt(pt, rng_);

            auto result_cts = eval_key.expands(ct, expansion_size);
            EXPECT_EQ(result_cts.size(), expansion_size);

            for (size_t j = 0; j < expansion_size; ++j) {
              std::vector<uint64_t> expected(params->degree(), 0);
              expected[0] =
                  (v[j] * expansion_size) % params->plaintext_modulus();

              auto result_pt = sk.decrypt(
                  result_cts[j], Encoding::poly_at_level(ciphertext_level));
              auto decoded_values = result_pt.decode_uint64(
                  Encoding::poly_at_level(ciphertext_level));

              EXPECT_EQ(decoded_values, expected)
                  << "Expansion failed for index " << j;
            }
          }
        }
      }
    }
  }
}

TEST_F(EvaluationKeyTest, CopyAndMoveSemantics) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    auto params_6 = BfvParameters::default_arc(6, 16);
    test_params.push_back(params_6);
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    auto sk = SecretKey::random(params, rng_);
    auto builder = EvaluationKeyBuilder::create(sk);
    builder.enable_inner_sum();
    auto eval_key = builder.build(rng_);

    // Test copy constructor
    auto eval_key_copy(eval_key);
    EXPECT_EQ(eval_key, eval_key_copy);
    EXPECT_TRUE(eval_key_copy.supports_inner_sum());

    // Test copy assignment
    auto builder2 = EvaluationKeyBuilder::create(sk);
    builder2.enable_row_rotation();
    auto eval_key_assign = builder2.build(rng_);
    eval_key_assign = eval_key;
    EXPECT_EQ(eval_key, eval_key_assign);
    EXPECT_TRUE(eval_key_assign.supports_inner_sum());

    // Test move constructor
    auto eval_key_move(std::move(eval_key_copy));
    EXPECT_TRUE(eval_key_move.supports_inner_sum());
    EXPECT_EQ(eval_key, eval_key_move);

    // Test move assignment
    auto builder3 = EvaluationKeyBuilder::create(sk);
    builder3.enable_row_rotation();
    auto eval_key_move_assign = builder3.build(rng_);
    eval_key_move_assign = std::move(eval_key_move);
    EXPECT_TRUE(eval_key_move_assign.supports_inner_sum());
    EXPECT_EQ(eval_key, eval_key_move_assign);
  }
}

TEST_F(EvaluationKeyTest, EqualityComparison) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    auto params_6 = BfvParameters::default_arc(6, 16);
    test_params.push_back(params_6);
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    auto sk = SecretKey::random(params, rng_);

    // Create two identical evaluation keys
    auto builder1 = EvaluationKeyBuilder::create(sk);
    builder1.enable_inner_sum();
    builder1.enable_row_rotation();
    auto eval_key1 = builder1.build(rng_);

    auto builder2 = EvaluationKeyBuilder::create(sk);
    builder2.enable_inner_sum();
    builder2.enable_row_rotation();
    auto eval_key2 = builder2.build(rng_);

    // Test equality
    EXPECT_EQ(eval_key1, eval_key1);  // Self equality
    // Note: eval_key1 and eval_key2 may not be equal due to randomness in key
    // generation

    // Test inequality
    auto builder3 = EvaluationKeyBuilder::create(sk);
    builder3.enable_inner_sum();  // Different operations enabled
    auto eval_key3 = builder3.build(rng_);

    EXPECT_NE(eval_key1, eval_key3);

    // Test copy equality
    auto eval_key_copy = eval_key1;
    EXPECT_EQ(eval_key1, eval_key_copy);
  }
}

TEST_F(EvaluationKeyTest, SerializationRoundTrip) {
  std::vector<std::shared_ptr<BfvParameters>> test_params;
  try {
    auto params_6 = BfvParameters::default_arc(6, 16);
    test_params.push_back(params_6);
  } catch (const std::exception &e) {
    GTEST_SKIP() << "Cannot create test parameters: " << e.what();
  }

  for (auto &params : test_params) {
    auto sk = SecretKey::random(params, rng_);
    auto builder = EvaluationKeyBuilder::create(sk);
    builder.enable_inner_sum();
    builder.enable_expansion(1);
    auto eval_key = builder.build(rng_);
    auto serialized = eval_key.Serialize();
    auto restored = EvaluationKey::from_bytes(serialized, params);

    EXPECT_EQ(restored, eval_key);
    EXPECT_TRUE(restored.supports_inner_sum());
    EXPECT_TRUE(restored.supports_row_rotation());
    EXPECT_TRUE(restored.supports_expansion(1));

    auto values = generate_random_values(params->degree(),
                                         params->plaintext_modulus() - 1);
    auto pt = Plaintext::encode(values, Encoding::simd(), params);
    auto ct = sk.encrypt(pt, rng_);
    auto result_ct = restored.computes_inner_sum(ct);
    auto result_pt = sk.decrypt(result_ct, Encoding::simd());
    auto decoded = result_pt.decode_uint64(Encoding::simd());

    uint64_t expected_sum = 0;
    for (auto value : values) {
      expected_sum = (expected_sum + value) % params->plaintext_modulus();
    }
    for (auto value : decoded) {
      EXPECT_EQ(value, expected_sum);
    }
  }
}
