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

class PlaintextTest : public ::testing::Test {};

TEST_F(PlaintextTest, AsTypeWorks) {
  Plaintext pt(SchemaType::ZPaillier);
  pt.SetValue(100);
  // The underlying type of ZPaillier is MPInt
  EXPECT_EQ(pt.As<MPInt>(), MPInt(100));

  pt.As<MPInt>() = MPInt(200);
  EXPECT_EQ(pt.GetValue<uint128_t>(), 200);

  MPInt var;
  pt.AsTypeLike(var) = MPInt(300);
  EXPECT_EQ(pt.GetValue<int64_t>(), 300);

  MPInt *varp = nullptr;
  pt.AsTypeLike(varp)->Set<int16_t>(400);
  EXPECT_EQ(pt.GetValue<uint16_t>(), 400);

  const Plaintext cpt(SchemaType::Mock, 1024);
  EXPECT_EQ(cpt.GetValue<uint32_t>(), 1024);
  EXPECT_TRUE(cpt.As<algorithms::mock::Plaintext>() ==
              cpt.AsTypeLike(algorithms::mock::Plaintext()));

  MPInt mp3(Plaintext(SchemaType::ZPaillier, 33).As<MPInt>());
  EXPECT_EQ(mp3.Get<uint8_t>(), 33);

  auto i64max = std::numeric_limits<int64_t>::max();
  int128_t i128 = static_cast<int128_t>(i64max) * i64max;
  Plaintext big(SchemaType::ZPaillier, i128);
  ASSERT_GE(big.BitCount(), 120);
  EXPECT_EQ(big.GetValue<int128_t>(), i128);
}

TEST_F(PlaintextTest, EqWorks) {
  EXPECT_FALSE(Plaintext().IsCompatible(SchemaType::Mock));
  EXPECT_FALSE(Plaintext().IsCompatible(SchemaType::ZPaillier));
  EXPECT_FALSE(Plaintext().IsCompatible(SchemaType::FPaillier));

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
  // compatible plaintexts are equal since the underlying types are same (MPInt)
  EXPECT_TRUE(Plaintext(SchemaType::FPaillier) ==
              Plaintext(SchemaType::ZPaillier));

  EXPECT_TRUE(Plaintext(SchemaType::ZPaillier, 1) ==
              Plaintext(SchemaType::ZPaillier, 1));
  EXPECT_TRUE(Plaintext(SchemaType::ZPaillier, 1) !=
              Plaintext(SchemaType::ZPaillier, 2));
  EXPECT_TRUE(Plaintext(SchemaType::ZPaillier, 100) !=
              Plaintext(SchemaType::Mock, 100));
}

TEST_F(PlaintextTest, ArithmeticWorks) {
  Plaintext pt1{algorithms::MPInt(100)};
  Plaintext pt2(algorithms::MPInt(200));
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
}

}  // namespace heu::lib::phe::test
