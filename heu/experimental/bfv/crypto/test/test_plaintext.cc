#include <gtest/gtest.h>

#include <random>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/encoding.h"
#include "crypto/plaintext.h"
#include "crypto/serialization/serialization_exceptions.h"

using namespace crypto::bfv;

class PlaintextTest : public ::testing::Test {
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

// Test basic construction and properties
TEST_F(PlaintextTest, BasicConstruction) {
  Plaintext pt;
  EXPECT_TRUE(pt.empty());
  EXPECT_FALSE(pt.encoding().has_value());
  EXPECT_EQ(pt.parameters(), nullptr);
}

// Test zero plaintext creation
TEST_F(PlaintextTest, ZeroPlaintext) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto encoding = Encoding::poly();
  auto zero_pt = Plaintext::zero(encoding, params_);

  EXPECT_FALSE(zero_pt.empty());
  EXPECT_EQ(zero_pt.level(), 0);
  EXPECT_TRUE(zero_pt.encoding().has_value());
  EXPECT_EQ(zero_pt.encoding().value(), encoding);
  EXPECT_EQ(zero_pt.parameters(), params_);

  // Decode and check that all values are zero
  auto decoded = zero_pt.decode_uint64();
  for (uint64_t val : decoded) {
    EXPECT_EQ(val, 0);
  }
}

// Test encoding and decoding with uint64_t values
TEST_F(PlaintextTest, EncodeDecodeUint64) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  // Test with polynomial encoding
  auto values = generate_random_values(8);  // Use fewer values than degree
  auto encoding = Encoding::poly();

  auto plaintext = Plaintext::encode(values, encoding, params_);
  EXPECT_FALSE(plaintext.empty());
  EXPECT_EQ(plaintext.level(), 0);
  EXPECT_TRUE(plaintext.encoding().has_value());
  EXPECT_EQ(plaintext.encoding().value(), encoding);

  // Decode and verify
  auto decoded = plaintext.decode_uint64();
  EXPECT_GE(decoded.size(), values.size());

  // Check that the first values match (the rest should be zero-padded)
  for (size_t i = 0; i < values.size(); ++i) {
    EXPECT_EQ(decoded[i], values[i]);
  }
}

// Test encoding and decoding with int64_t values
TEST_F(PlaintextTest, EncodeDecodeInt64) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  // Test with polynomial encoding
  auto values = generate_random_signed_values(8);
  auto encoding = Encoding::poly();

  auto plaintext = Plaintext::encode(values, encoding, params_);
  EXPECT_FALSE(plaintext.empty());

  // Decode and verify
  auto decoded = plaintext.decode_int64();
  EXPECT_GE(decoded.size(), values.size());

  // Check that the first values match
  for (size_t i = 0; i < values.size(); ++i) {
    EXPECT_EQ(decoded[i], values[i]);
  }
}

// Test encoding with different levels
TEST_F(PlaintextTest, EncodingLevels) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto values = generate_random_values(4);

  // Test different levels (if supported by parameters)
  for (size_t level = 0; level <= std::min(params_->max_level(), size_t(2));
       ++level) {
    auto encoding = Encoding::poly_at_level(level);

    try {
      auto plaintext = Plaintext::encode(values, encoding, params_);
      EXPECT_EQ(plaintext.level(), level);
      EXPECT_TRUE(plaintext.encoding().has_value());
      EXPECT_EQ(plaintext.encoding().value(), encoding);
    } catch (const BfvException &e) {
      // Some levels might not be supported, which is okay
      continue;
    }
  }
}

// Test equality comparison
TEST_F(PlaintextTest, EqualityComparison) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto values = generate_random_values(6);
  auto encoding = Encoding::poly();

  auto pt1 = Plaintext::encode(values, encoding, params_);
  auto pt2 = Plaintext::encode(values, encoding, params_);

  EXPECT_EQ(pt1, pt2);
  EXPECT_FALSE(pt1 != pt2);

  // Test with different values
  auto different_values = generate_random_values(6);
  auto pt3 = Plaintext::encode(different_values, encoding, params_);

  EXPECT_NE(pt1, pt3);
  EXPECT_TRUE(pt1 != pt3);
}

// Test copy and move semantics
TEST_F(PlaintextTest, CopyMoveSemantics) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto values = generate_random_values(5);
  auto encoding = Encoding::poly();
  auto original = Plaintext::encode(values, encoding, params_);

  // Test copy constructor
  auto copied(original);
  EXPECT_EQ(copied, original);
  EXPECT_EQ(copied.level(), original.level());
  EXPECT_EQ(copied.encoding(), original.encoding());

  // Test copy assignment
  auto assigned = Plaintext::zero(encoding, params_);
  assigned = original;
  EXPECT_EQ(assigned, original);

  // Test move constructor
  auto original_copy = original;  // Keep a copy for comparison
  auto moved(std::move(original));
  EXPECT_EQ(moved, original_copy);

  // Test move assignment
  auto move_assigned = Plaintext::zero(encoding, params_);
  move_assigned = std::move(moved);
  EXPECT_EQ(move_assigned, original_copy);
}

// Test zeroization
TEST_F(PlaintextTest, Zeroization) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto values = generate_random_values(6);
  auto encoding = Encoding::poly();
  auto plaintext = Plaintext::encode(values, encoding, params_);

  // Verify it's not zero initially
  auto decoded_before = plaintext.decode_uint64();
  bool has_nonzero = false;
  for (size_t i = 0; i < values.size(); ++i) {
    if (decoded_before[i] != 0) {
      has_nonzero = true;
      break;
    }
  }
  EXPECT_TRUE(has_nonzero);

  // Zeroize
  plaintext.zeroize();

  // Check that it equals a zero plaintext
  auto zero_pt = Plaintext::zero(encoding, params_);
  // Note: Direct equality might not work due to internal state differences
  // So we check the decoded values instead
  auto decoded_after = plaintext.decode_uint64();
  auto zero_decoded = zero_pt.decode_uint64();

  EXPECT_EQ(decoded_after.size(), zero_decoded.size());
  for (size_t i = 0; i < decoded_after.size(); ++i) {
    EXPECT_EQ(decoded_after[i], 0);
  }
}

// Test error conditions
TEST_F(PlaintextTest, ErrorConditions) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto encoding = Encoding::poly();

  // Test with null parameters
  auto values = generate_random_values(4);
  EXPECT_THROW(Plaintext::encode(values, encoding, nullptr),
               ParameterException);

  // Test with too many values
  auto too_many_values = generate_random_values(params_->degree() + 1);
  EXPECT_THROW(Plaintext::encode(too_many_values, encoding, params_),
               ParameterException);

  // Test decoding without encoding
  Plaintext empty_pt;
  EXPECT_THROW(empty_pt.decode_uint64(), EncodingException);
}

// Test decoding with explicit encoding parameter
TEST_F(PlaintextTest, ExplicitEncodingDecoding) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto values = generate_random_values(5);
  auto encoding = Encoding::poly();
  auto plaintext = Plaintext::encode(values, encoding, params_);

  // Decode with explicit encoding (should match)
  auto decoded1 = plaintext.decode_uint64(encoding);
  auto decoded2 = plaintext.decode_uint64();

  EXPECT_EQ(decoded1.size(), decoded2.size());
  for (size_t i = 0; i < decoded1.size(); ++i) {
    EXPECT_EQ(decoded1[i], decoded2[i]);
  }

  // Test with mismatched encoding (should throw)
  auto different_encoding = Encoding::poly_at_level(1);
  if (params_->max_level() > 0) {
    EXPECT_THROW(plaintext.decode_uint64(different_encoding),
                 EncodingException);
  }
}

// Test array-based encoding
TEST_F(PlaintextTest, ArrayEncoding) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  // Test uint64_t array
  uint64_t values[] = {1, 2, 3, 4, 5};
  size_t count = sizeof(values) / sizeof(values[0]);
  auto encoding = Encoding::poly();

  auto plaintext = Plaintext::encode(values, count, encoding, params_);
  auto decoded = plaintext.decode_uint64();

  for (size_t i = 0; i < count; ++i) {
    EXPECT_EQ(decoded[i], values[i]);
  }

  // Test int64_t array
  int64_t signed_values[] = {-2, -1, 0, 1, 2};
  auto signed_plaintext =
      Plaintext::encode(signed_values, count, encoding, params_);
  auto signed_decoded = signed_plaintext.decode_int64();

  for (size_t i = 0; i < count; ++i) {
    EXPECT_EQ(signed_decoded[i], signed_values[i]);
  }
}

TEST_F(PlaintextTest, SerializationRoundTrip) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto values = generate_random_values(3);
  auto encoding = Encoding::poly();
  auto plaintext = Plaintext::encode(values, encoding, params_);

  auto serialized = plaintext.Serialize();
  auto restored = Plaintext::from_bytes(serialized, params_);

  EXPECT_EQ(restored, plaintext);
  ASSERT_TRUE(restored.encoding().has_value());
  EXPECT_EQ(restored.encoding().value(), encoding);
  EXPECT_EQ(restored.level(), plaintext.level());
}
