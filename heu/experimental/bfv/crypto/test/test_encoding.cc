#include <gtest/gtest.h>

#include "crypto/encoding.h"

using namespace crypto::bfv;

class EncodingTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Setup code if needed
  }

  void TearDown() override {
    // Cleanup code if needed
  }
};

// Test factory methods
TEST_F(EncodingTest, FactoryMethods) {
  // Test poly() factory method
  auto poly_enc = Encoding::poly();
  EXPECT_EQ(poly_enc.encoding_type(), EncodingType::Poly);
  EXPECT_EQ(poly_enc.level(), 0);

  // Test simd() factory method
  auto simd_enc = Encoding::simd();
  EXPECT_EQ(simd_enc.encoding_type(), EncodingType::Simd);
  EXPECT_EQ(simd_enc.level(), 0);

  // Test poly_at_level() factory method
  auto poly_level_enc = Encoding::poly_at_level(3);
  EXPECT_EQ(poly_level_enc.encoding_type(), EncodingType::Poly);
  EXPECT_EQ(poly_level_enc.level(), 3);

  // Test simd_at_level() factory method
  auto simd_level_enc = Encoding::simd_at_level(5);
  EXPECT_EQ(simd_level_enc.encoding_type(), EncodingType::Simd);
  EXPECT_EQ(simd_level_enc.level(), 5);
}

// Test equality and inequality operators
TEST_F(EncodingTest, EqualityOperators) {
  auto poly1 = Encoding::poly();
  auto poly2 = Encoding::poly();
  auto simd1 = Encoding::simd();
  auto poly_level = Encoding::poly_at_level(1);

  // Test equality
  EXPECT_EQ(poly1, poly2);
  EXPECT_TRUE(poly1 == poly2);

  // Test inequality - different types
  EXPECT_NE(poly1, simd1);
  EXPECT_TRUE(poly1 != simd1);

  // Test inequality - different levels
  EXPECT_NE(poly1, poly_level);
  EXPECT_TRUE(poly1 != poly_level);

  // Test equality with same type and level
  auto simd2 = Encoding::simd();
  EXPECT_EQ(simd1, simd2);
  EXPECT_TRUE(simd1 == simd2);
}

// Test copy constructor and assignment
TEST_F(EncodingTest, CopySemantics) {
  auto original = Encoding::simd_at_level(2);

  // Test copy constructor
  auto copied(original);
  EXPECT_EQ(copied, original);
  EXPECT_EQ(copied.encoding_type(), EncodingType::Simd);
  EXPECT_EQ(copied.level(), 2);

  // Test copy assignment
  auto assigned = Encoding::poly();
  assigned = original;
  EXPECT_EQ(assigned, original);
  EXPECT_EQ(assigned.encoding_type(), EncodingType::Simd);
  EXPECT_EQ(assigned.level(), 2);
}

// Test move constructor and assignment
TEST_F(EncodingTest, MoveSemantics) {
  auto original = Encoding::poly_at_level(4);
  auto original_copy = original;  // Keep a copy for comparison

  // Test move constructor
  auto moved(std::move(original));
  EXPECT_EQ(moved, original_copy);
  EXPECT_EQ(moved.encoding_type(), EncodingType::Poly);
  EXPECT_EQ(moved.level(), 4);

  // Test move assignment
  auto move_assigned = Encoding::simd();
  move_assigned = std::move(moved);
  EXPECT_EQ(move_assigned, original_copy);
  EXPECT_EQ(move_assigned.encoding_type(), EncodingType::Poly);
  EXPECT_EQ(move_assigned.level(), 4);
}

// Test string representation
TEST_F(EncodingTest, StringRepresentation) {
  auto poly_enc = Encoding::poly();
  auto simd_enc = Encoding::simd_at_level(3);

  std::string poly_str = poly_enc.to_string();
  std::string simd_str = simd_enc.to_string();

  // Check that string contains expected information
  EXPECT_NE(poly_str.find("Poly"), std::string::npos);
  EXPECT_NE(poly_str.find("level: 0"), std::string::npos);

  EXPECT_NE(simd_str.find("Simd"), std::string::npos);
  EXPECT_NE(simd_str.find("level: 3"), std::string::npos);
}

// Test default constructor
TEST_F(EncodingTest, DefaultConstructor) {
  Encoding default_enc;
  EXPECT_EQ(default_enc.encoding_type(), EncodingType::Poly);
  EXPECT_EQ(default_enc.level(), 0);

  // Should be equal to poly()
  auto poly_enc = Encoding::poly();
  EXPECT_EQ(default_enc, poly_enc);
}

// Test various level values
TEST_F(EncodingTest, VariousLevels) {
  // Test with different level values
  std::vector<size_t> levels = {0, 1, 5, 10, 100};

  for (size_t level : levels) {
    auto poly_enc = Encoding::poly_at_level(level);
    auto simd_enc = Encoding::simd_at_level(level);

    EXPECT_EQ(poly_enc.level(), level);
    EXPECT_EQ(simd_enc.level(), level);
    EXPECT_EQ(poly_enc.encoding_type(), EncodingType::Poly);
    EXPECT_EQ(simd_enc.encoding_type(), EncodingType::Simd);

    // Different types at same level should not be equal
    EXPECT_NE(poly_enc, simd_enc);
  }
}

// Test self-assignment
TEST_F(EncodingTest, SelfAssignment) {
  auto enc = Encoding::simd_at_level(7);
  auto original = enc;

  // Self-assignment should not change the object
  enc = enc;
  EXPECT_EQ(enc, original);
  EXPECT_EQ(enc.encoding_type(), EncodingType::Simd);
  EXPECT_EQ(enc.level(), 7);
}
