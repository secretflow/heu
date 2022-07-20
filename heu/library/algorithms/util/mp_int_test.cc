// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "heu/library/algorithms/util/mp_int.h"

#include "gtest/gtest.h"

namespace heu::lib::algorithms::test {

class MPIntTest : public testing::Test {};

TEST_F(MPIntTest, CompareWorks) {
  MPInt x1(256);
  MPInt x2(257);

  EXPECT_TRUE(x1.Compare(x2) < 0);
  EXPECT_TRUE(x1 < x2);
  EXPECT_TRUE(x1 <= x2);
  EXPECT_TRUE(x2 > x1);
  EXPECT_TRUE(x2 >= x1);
}

TEST_F(MPIntTest, ArithmeticWorks) {
  MPInt x1(23);
  MPInt x2(37);

  EXPECT_TRUE(x1 + x2 == MPInt(23 + 37));
  EXPECT_TRUE(x2 + x1 == MPInt(37 + 23));
  EXPECT_TRUE(x1 - x2 == MPInt(23 - 37));
  EXPECT_TRUE(x2 - x1 == MPInt(37 - 23));
  EXPECT_TRUE(x1 * x2 == MPInt(23 * 37));
  EXPECT_TRUE(x2 * x1 == MPInt(37 * 23));
  EXPECT_TRUE(x1 / x2 == MPInt(23 / 37));
  EXPECT_TRUE(x2 / x1 == MPInt(37 / 23));
}

TEST_F(MPIntTest, DefaultCtorWorks) {
  MPInt x;

  EXPECT_TRUE(x.IsZero());
}

TEST_F(MPIntTest, CtorWorks) {
  MPInt x1(-123456);
  MPInt x2(2345);

  EXPECT_TRUE(x1.IsNegative());
  EXPECT_FALSE(x2.IsNegative());
  EXPECT_TRUE(x1.Compare(x2) < 0);
}

TEST_F(MPIntTest, InvertModWorks) {
  MPInt a(667);
  MPInt::InvertMod(a, MPInt(561613), &a);
  EXPECT_EQ(842, a.As<double>());
}

TEST_F(MPIntTest, ToStringWorks) {
  MPInt x1;
  MPInt x2((int64_t)0x12345abcdef);

  EXPECT_EQ(x1.ToHexString(), "0");
  EXPECT_EQ(x2.ToHexString(), "12345ABCDEF");
}

TEST_F(MPIntTest, NegativeMPIntToStringWorks) {
  MPInt x1(-12345678);
  ASSERT_TRUE(x1.IsNegative());
  EXPECT_EQ(x1.ToString(), "-12345678");
  EXPECT_EQ(x1.ToHexString(), "-BC614E");
}

TEST_F(MPIntTest, SerializationAndDeserializationWorks) {
  MPInt x1(1234567890);
  MPInt x2(-1234567890);
  std::string x1_repr, x2_repr;

  x1.Serialize(&x1_repr);
  x2.Serialize(&x2_repr);

  ASSERT_TRUE(x1_repr.size() > 0);
  ASSERT_TRUE(x2_repr.size() > 0);

  MPInt x1_value, x2_value;
  EXPECT_TRUE(MPInt::Deserialize(x1_repr, &x1_value));
  EXPECT_TRUE(MPInt::Deserialize(x2_repr, &x2_value));

  EXPECT_TRUE(x1.Compare(x1_value) == 0);
  EXPECT_TRUE(x2.Compare(x2_value) == 0);
}

TEST_F(MPIntTest, RandPrimeOverWorks) {
  const int bit_size = 256;
  MPInt x;
  MPInt::RandPrimeOver(bit_size, &x);

  EXPECT_GE(x.BitCount(), bit_size);
}

TEST_F(MPIntTest, RandomWorks) {
  int bit_size = 240;
  MPInt r;
  MPInt::RandomRoundDown(bit_size, &r);  // 240 bits

  EXPECT_LE(r.BitCount(), bit_size);
  // The probability that the first 20 digits are all 0 is less than 2^20
  EXPECT_GE(r.BitCount(), bit_size - 20);

  MPInt::RandomRoundUp(bit_size, &r);  // 240 bits
  EXPECT_LE(r.BitCount(), bit_size);
  EXPECT_GE(r.BitCount(), bit_size - 20);

  bit_size = 105;
  MPInt::RandomRoundDown(bit_size, &r);  // 60 bits
  EXPECT_LE(r.BitCount(), 60);
  EXPECT_GE(r.BitCount(), 60 - 20);

  MPInt::RandomRoundUp(bit_size, &r);  // 120 bits
  EXPECT_LE(r.BitCount(), 120);
  EXPECT_GE(r.BitCount(), 120 - 20);
}

}  // namespace heu::lib::algorithms::test
