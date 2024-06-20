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

#include "heu/library/phe/encoding/batch_encoder.h"

#include "fmt/format.h"
#include "gtest/gtest.h"

namespace heu::lib::phe::test {

class BatchEncoderTest : public testing::Test {
 protected:
  template <class T>
  void EncodingTest(const BatchEncoder &be, T a, T b) {
    auto var_info = [&]() {
      return fmt::format("Encoder={}, a={}, b={}", be.ToString(), a, b);
    };

    auto pt = be.Encode<T>(a, b);
    EXPECT_EQ((be.Decode<T, 0>(pt)), a) << var_info();
    EXPECT_EQ((be.Decode<T, 1>(pt)), b) << var_info();

    auto pt2 = pt + be.Encode<T>(2, 1);
    EXPECT_EQ((be.Decode<T, 0>(pt2)), static_cast<T>(a + 2)) << var_info();
    EXPECT_EQ((be.Decode<T, 1>(pt2)), static_cast<T>(b + 1)) << var_info();

    // case of overflow
    pt2 = pt * Plaintext(SchemaType::ZPaillier, 1000);
    EXPECT_EQ((be.Decode<T, 0>(pt2)),
              static_cast<T>(a * 1000 * be.GetScale()) / be.GetScale())
        << var_info();
    EXPECT_EQ((be.Decode<T, 1>(pt2)),
              static_cast<T>(b * 1000 * be.GetScale()) / be.GetScale())
        << var_info();
  }
};

TEST_F(BatchEncoderTest, SerializeWorks) {
  BatchEncoder be1(SchemaType::FPaillier, 10000, 12);
  BatchEncoder be2 = BatchEncoder::LoadFrom(be1.Serialize());
  EXPECT_EQ(be2.GetSchema(), SchemaType::FPaillier);
  EXPECT_EQ(be2.GetScale(), 10000);
  EXPECT_EQ(be2.GetPaddingBits(), 12);
}

TEST_F(BatchEncoderTest, EncodingIntWorks) {
  const BatchEncoder bes[] = {BatchEncoder(SchemaType::ZPaillier),
                              BatchEncoder(SchemaType::ZPaillier, 2),
                              BatchEncoder(SchemaType::ZPaillier, 10, 16)};

  for (const auto &be : bes) {
    EncodingTest<uint8_t>(be, 1, 6);
    EncodingTest<uint16_t>(be, 10, 60);
    EncodingTest<uint32_t>(be, 100, 6000);
    EncodingTest<uint64_t>(be, 1000, 60000);
    EncodingTest<uint128_t>(be, 50000, 600000);

    EncodingTest<int8_t>(be, 1, 6);
    EncodingTest<int16_t>(be, 10, 60);
    EncodingTest<int32_t>(be, 100, 6000);
    EncodingTest<int64_t>(be, 1000, 60000);
    EncodingTest<int128_t>(be, 50000, 600000);

    EncodingTest<int8_t>(be, 1, -6);
    EncodingTest<int16_t>(be, 10, -60);
    EncodingTest<int32_t>(be, 100, -6000);
    EncodingTest<int64_t>(be, 1000, -60000);
    EncodingTest<int128_t>(be, 50000, -600000);

    EncodingTest<int8_t>(be, -1, 6);
    EncodingTest<int16_t>(be, -10, 60);
    EncodingTest<int32_t>(be, -100, 6000);
    EncodingTest<int64_t>(be, -1000, 60000);
    EncodingTest<int128_t>(be, -50000, 600000);

    EncodingTest<int8_t>(be, -1, -6);
    EncodingTest<int16_t>(be, -10, -60);
    EncodingTest<int32_t>(be, -100, -6000);
    EncodingTest<int64_t>(be, -1000, -60000);
    EncodingTest<int128_t>(be, -50000, -600000);
  }
}

TEST_F(BatchEncoderTest, EncodingFloatWorks) {
  BatchEncoder be(SchemaType::ZPaillier, 1000);
  auto pt1 = be.Encode(4.5, 93.72);
  auto pt2 = be.Encode(10.9, 2.4);
  auto pt3 = pt1 + pt2;
  EXPECT_EQ((be.Decode<double, 0>(pt3)), 4.5 + 10.9);
  EXPECT_EQ((be.Decode<double, 1>(pt3)), 93.72 + 2.4);
}

TEST_F(BatchEncoderTest, PlusWorks) {
  BatchEncoder be1(SchemaType::ZPaillier, 64, 31);
  auto buf = be1.Serialize();
  BatchEncoder be2 = BatchEncoder::LoadFrom(buf);

  auto pt = be1.Encode<int64_t>(0, 0);
  int64_t sum_a = 0, sum_b = 0;
  for (int64_t n = 0; n > 0; n += INT64_MAX / 100000) {
    pt += be1.Encode<int64_t>(-n, n);
    sum_a -= n;
    sum_b += n;
    EXPECT_EQ((be2.Decode<int64_t, 0>(pt)), sum_a);
    EXPECT_EQ((be2.Decode<int64_t, 1>(pt)), sum_b);
  }
}

TEST_F(BatchEncoderTest, PlusSubWorks) {
  BatchEncoder be(SchemaType::ZPaillier, 64);
  auto pt = be.Encode<int64_t>(0, 0);
  int64_t sum = 0;
  int64_t sign = -1;
  for (int64_t n = 0; n > 0; n += INT64_MAX / 100000) {
    sign *= -1;
    pt += be.Encode<int64_t>(n * sign, n * sign);
    sum += n * sign;
    EXPECT_EQ((be.Decode<int64_t, 0>(pt)), sum);
    EXPECT_EQ((be.Decode<int64_t, 1>(pt)), sum);
  }
}

}  // namespace heu::lib::phe::test
