#include "math/representation.h"

#include <gtest/gtest.h>

namespace bfv::math::rq {

/**
 * @brief Test representation enum values
 *
 * - PowerBasis = 0 (default)
 * - Ntt = 1
 * - NttShoup = 2
 */
TEST(RepresentationTest, EnumValues) {
  // Test that PowerBasis is the default (value 0)
  EXPECT_EQ(static_cast<int>(Representation::PowerBasis), 0);
  EXPECT_EQ(static_cast<int>(Representation::Ntt), 1);
  EXPECT_EQ(static_cast<int>(Representation::NttShoup), 2);

  // Test default construction gives PowerBasis
  Representation default_repr = Representation::PowerBasis;
  EXPECT_EQ(default_repr, Representation::PowerBasis);
}

/**
 * @brief Test string conversion functions.
 *
 * This test verifies that string conversion works correctly and matches
 * the expected string representations.
 */
TEST(RepresentationTest, StringConversion) {
  // Test to_string conversion
  EXPECT_STREQ(representation_to_string(Representation::PowerBasis),
               "PowerBasis");
  EXPECT_STREQ(representation_to_string(Representation::Ntt), "Ntt");
  EXPECT_STREQ(representation_to_string(Representation::NttShoup), "NttShoup");

  // Test from_string conversion
  EXPECT_EQ(representation_from_string("PowerBasis"),
            Representation::PowerBasis);
  EXPECT_EQ(representation_from_string("Ntt"), Representation::Ntt);
  EXPECT_EQ(representation_from_string("NttShoup"), Representation::NttShoup);

  // Test round-trip conversion
  for (auto repr : {Representation::PowerBasis, Representation::Ntt,
                    Representation::NttShoup}) {
    std::string str = representation_to_string(repr);
    Representation converted = representation_from_string(str);
    EXPECT_EQ(converted, repr);
  }
}

/**
 * @brief Test invalid string conversion throws exception.
 */
TEST(RepresentationTest, InvalidStringConversion) {
  EXPECT_THROW(representation_from_string("Invalid"), std::invalid_argument);
  EXPECT_THROW(representation_from_string(""), std::invalid_argument);
  EXPECT_THROW(representation_from_string("powerbasis"),
               std::invalid_argument);  // case sensitive
}

}  // namespace bfv::math::rq
