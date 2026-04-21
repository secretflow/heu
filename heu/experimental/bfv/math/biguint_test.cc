#include "math/biguint.h"

#include <gtest/gtest.h>

using namespace bfv::math::rns;

TEST(BigUintTest, Constructors) {
  BigUint zero = BigUint::zero();
  EXPECT_EQ(zero, BigUint(0));

  BigUint one = BigUint::one();
  EXPECT_EQ(one, BigUint(1));

  BigUint val(1234567890ULL);
  EXPECT_EQ(val.to_u64(), 1234567890ULL);
}

TEST(BigUintTest, Arithmetic) {
  BigUint a(100);
  BigUint b(200);

  EXPECT_EQ(a + b, BigUint(300));
  EXPECT_EQ(b - a, BigUint(100));
  EXPECT_EQ(a * b, BigUint(20000));
  EXPECT_EQ(b / a, BigUint(2));
  EXPECT_EQ(b % a, BigUint(0));

  BigUint c = a;
  c += b;
  EXPECT_EQ(c, BigUint(300));

  c = b;
  c -= a;
  EXPECT_EQ(c, BigUint(100));

  c = a;
  c *= b;
  EXPECT_EQ(c, BigUint(20000));

  c = b;
  c /= a;
  EXPECT_EQ(c, BigUint(2));

  c = b;
  c %= a;
  EXPECT_EQ(c, BigUint(0));
}

TEST(BigUintTest, Comparisons) {
  BigUint a(100);
  BigUint b(200);

  EXPECT_TRUE(a < b);
  EXPECT_TRUE(b > a);
  EXPECT_TRUE(a <= b);
  EXPECT_TRUE(b >= a);
  EXPECT_TRUE(a != b);
  EXPECT_FALSE(a == b);
}

TEST(BigUintTest, ModInverse) {
  BigUint modulus(13);
  BigUint val(3);
  auto inv = val.mod_inverse(modulus);
  EXPECT_TRUE(inv.has_value());
  EXPECT_EQ(inv.value(), BigUint(9));  // 3*9=27=1 mod 13
}

TEST(BigUintTest, Shifts) {
  BigUint a(1);
  EXPECT_EQ(a << 3, BigUint(8));
  EXPECT_EQ(a >> 1, BigUint(0));
}
