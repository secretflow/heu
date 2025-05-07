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

#include "heu/library/phe/base/plaintext.h"

#include "gtest/gtest.h"

namespace heu::lib::phe::test {

using algorithms::BigInt;

TEST(PlaintextTest, AsTypeWorks) {
  Plaintext pt(SchemaType::ZPaillier);
  pt.SetValue(100);
  // The underlying type of ZPaillier is BigInt
  EXPECT_EQ(pt.As<BigInt>(), 100);

  pt.As<BigInt>() = 200;
  EXPECT_EQ(pt.GetValue<uint128_t>(), 200);

  BigInt var;
  pt.AsTypeLike(var) = BigInt(300);
  EXPECT_EQ(pt.GetValue<int64_t>(), 300);

  BigInt *varp = nullptr;
  pt.AsTypeLike(varp)->Set<int16_t>(400);
  EXPECT_EQ(pt.GetValue<uint16_t>(), 400);

  const Plaintext cpt(SchemaType::Mock, 1024);
  EXPECT_EQ(cpt.GetValue<uint32_t>(), 1024);
  EXPECT_TRUE(cpt.As<algorithms::mock::Plaintext>() ==
              cpt.AsTypeLike(algorithms::mock::Plaintext()));

  BigInt mp3(Plaintext(SchemaType::ZPaillier, 33).As<BigInt>());
  EXPECT_EQ(mp3.Get<uint8_t>(), 33);

  auto i64max = std::numeric_limits<int64_t>::max();
  int128_t i128 = static_cast<int128_t>(i64max) * i64max;
  Plaintext big(SchemaType::ZPaillier, i128);
  ASSERT_GE(big.BitCount(), 120);
  EXPECT_EQ(big.GetValue<int128_t>(), i128);
}

TEST(PlaintextTest, EqWorks) {
  Plaintext pt(SchemaType::ZPaillier);
  EXPECT_TRUE(pt.IsCompatible(SchemaType::ZPaillier));
  EXPECT_TRUE(pt.IsCompatible(SchemaType::FPaillier));
  EXPECT_FALSE(pt.IsCompatible(SchemaType::Mock));
  EXPECT_TRUE(pt.IsHoldType<algorithms::paillier_z::Plaintext>());
  EXPECT_FALSE(pt.IsHoldType<algorithms::mock::Plaintext>());

  EXPECT_TRUE(Plaintext() == Plaintext());
  EXPECT_TRUE(Plaintext() != Plaintext(SchemaType::ZPaillier));
  EXPECT_TRUE(Plaintext() != Plaintext(SchemaType::FPaillier));
  EXPECT_TRUE(Plaintext() != Plaintext(SchemaType::Mock));
  EXPECT_TRUE(Plaintext(SchemaType::Mock) != Plaintext(SchemaType::ZPaillier));
  // compatible plaintexts are equal since the underlying types are same
  // (BigInt)
  EXPECT_TRUE(Plaintext(SchemaType::FPaillier) ==
              Plaintext(SchemaType::ZPaillier));

  EXPECT_TRUE(Plaintext(SchemaType::ZPaillier, 1) ==
              Plaintext(SchemaType::ZPaillier, 1));
  EXPECT_TRUE(Plaintext(SchemaType::ZPaillier, 1) !=
              Plaintext(SchemaType::ZPaillier, 2));
  EXPECT_TRUE(Plaintext(SchemaType::ZPaillier, 100) !=
              Plaintext(SchemaType::Mock, 100));
}

class PlaintextTest : public ::testing::TestWithParam<SchemaType> {};

INSTANTIATE_TEST_SUITE_P(Schema, PlaintextTest,
                         ::testing::ValuesIn(GetAllSchema()));

TEST_P(PlaintextTest, GetSetWorks) {
  SchemaType schema = GetParam();
  EXPECT_FALSE(Plaintext().IsCompatible(schema));

  Plaintext pt(schema);
  EXPECT_TRUE(pt.IsCompatible(schema));

  pt.SetValue(127L);
  EXPECT_TRUE(pt.IsPositive());
  EXPECT_FALSE(pt.IsZero());
  EXPECT_FALSE(pt.IsNegative());

  EXPECT_EQ(pt.GetValue<uint8_t>(), 127);
  EXPECT_EQ(pt.GetValue<int8_t>(), 127);
  EXPECT_EQ(pt.GetValue<uint16_t>(), 127);
  EXPECT_EQ(pt.GetValue<int16_t>(), 127);
  EXPECT_EQ(pt.GetValue<uint32_t>(), 127);
  EXPECT_EQ(pt.GetValue<int32_t>(), 127);
  EXPECT_EQ(pt.GetValue<uint64_t>(), 127);
  EXPECT_EQ(pt.GetValue<int64_t>(), 127);
  EXPECT_EQ(pt.GetValue<uint128_t>(), 127);
  EXPECT_EQ(pt.GetValue<int128_t>(), 127);

  int128_t var = -128;
  pt.SetValue(var);
  EXPECT_EQ(pt.GetValue<int8_t>(), var);
  EXPECT_EQ(pt.GetValue<int16_t>(), var);
  EXPECT_EQ(pt.GetValue<int32_t>(), var);
  EXPECT_EQ(pt.GetValue<int64_t>(), var);
  EXPECT_EQ(pt.GetValue<int128_t>(), var);

  var = -127;
  pt.SetValue(static_cast<int8_t>(--var));
  EXPECT_EQ(pt.GetValue<int8_t>(), var);
  pt.SetValue(static_cast<int16_t>(--var));
  EXPECT_EQ(pt.GetValue<int16_t>(), var);
  pt.SetValue(static_cast<int32_t>(--var));
  EXPECT_EQ(pt.GetValue<int32_t>(), var);
  pt.SetValue(static_cast<int64_t>(--var));
  EXPECT_EQ(pt.GetValue<int64_t>(), var);
  pt.SetValue(static_cast<int128_t>(--var));
  EXPECT_EQ(pt.GetValue<int128_t>(), var);

  auto i64max = std::numeric_limits<int64_t>::max();
  int128_t i128 = static_cast<int128_t>(i64max) * i64max;
  Plaintext big(schema, i128);
  ASSERT_GE(big.BitCount(), 120);
  EXPECT_EQ(big.GetValue<int128_t>(), i128);
}

TEST_P(PlaintextTest, ArithmeticWorks) {
  Plaintext pt1{GetParam(), 100};
  Plaintext pt2(GetParam(), 200);
  EXPECT_TRUE(pt1 < pt2);
  EXPECT_TRUE(pt1 <= pt2);
  EXPECT_TRUE(pt1 != pt2);
  EXPECT_FALSE(pt1 == pt2);
  EXPECT_FALSE(pt1 >= pt2);
  EXPECT_FALSE(pt1 > pt2);

  EXPECT_EQ((pt1 + pt2).GetValue<int64_t>(), 300);
  EXPECT_EQ((pt1 - pt2).GetValue<int64_t>(), -100);
  EXPECT_EQ((pt1 * pt2).GetValue<int64_t>(), 20000);
  EXPECT_EQ((pt2 / pt1).GetValue<int64_t>(), 2);
  EXPECT_EQ((pt1 % pt2).GetValue<int64_t>(), 100);
  EXPECT_EQ((-pt1).GetValue<int64_t>(), -100);

  EXPECT_EQ((pt1 & pt2).GetValue<int64_t>(), 64);
  EXPECT_EQ((pt1 | pt2).GetValue<int64_t>(), 236);
  EXPECT_EQ((pt1 ^ pt2).GetValue<int64_t>(), 172);
  EXPECT_EQ((pt1 << 2).GetValue<int64_t>(), 400);
  EXPECT_EQ((pt1 >> 2).GetValue<int64_t>(), 25);

  int128_t v1 = 123456789;
  int128_t v2 = 123456;
  pt1.SetValue(v1);
  pt2.SetValue(v2);

  EXPECT_EQ((pt1 += pt2).GetValue<int128_t>(), v1 += v2);
  EXPECT_EQ((pt1 -= pt2).GetValue<int128_t>(), v1 -= v2);
  EXPECT_EQ((pt1 *= pt2).GetValue<int128_t>(), v1 *= v2);
  EXPECT_EQ((pt1 /= pt2).GetValue<int128_t>(), v1 /= v2);
  EXPECT_EQ((pt1 %= pt2).GetValue<int128_t>(), v1 %= v2);

  EXPECT_EQ((pt1 &= pt2).GetValue<int128_t>(), v1 &= v2);
  EXPECT_EQ((pt1 |= pt2).GetValue<int128_t>(), v1 |= v2);
  EXPECT_EQ((pt1 ^= pt2).GetValue<int128_t>(), v1 ^= v2);
  EXPECT_EQ((pt1 <<= 10).GetValue<int128_t>(), v1 <<= 10);
  EXPECT_EQ((pt1 >>= 10).GetValue<int128_t>(), v1 >>= 10);

  pt1.NegateInplace();
  EXPECT_EQ(pt1.GetValue<int128_t>(), -v1);
}

}  // namespace heu::lib::phe::test
