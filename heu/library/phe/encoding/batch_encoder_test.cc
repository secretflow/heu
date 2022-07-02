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

#include "gtest/gtest.h"

namespace heu::lib::phe::test {

class BatchEncoderTest : public testing::Test {
 protected:
  template <class T>
  void EncodingTest(T a, T b) {
    auto pt = batch_encoder_.Encode<T>(a, b);
    EXPECT_EQ((batch_encoder_.Get<T, 0>(pt)), a);
    EXPECT_EQ((batch_encoder_.Get<T, 1>(pt)), b);

    auto pt2 = pt + batch_encoder_.Encode<T>(2, 1);
    EXPECT_EQ((batch_encoder_.Get<T, 0>(pt2)), static_cast<T>(a + 2));
    EXPECT_EQ((batch_encoder_.Get<T, 1>(pt2)), static_cast<T>(b + 1));

    pt2 = pt * algorithms::Plaintext(1000);
    EXPECT_EQ((batch_encoder_.Get<T, 0>(pt2)), static_cast<T>(a * 1000));
    EXPECT_EQ((batch_encoder_.Get<T, 1>(pt2)), static_cast<T>(b * 1000));
  }

 protected:
  BatchEncoder batch_encoder_;
};

TEST_F(BatchEncoderTest, EncodingWorks) {
  EncodingTest<uint8_t>(1, 6);
  EncodingTest<uint16_t>(10, 60);
  EncodingTest<uint32_t>(100, 6000);
  EncodingTest<uint64_t>(1000, 60000);

  EncodingTest<int8_t>(1, 6);
  EncodingTest<int16_t>(10, 60);
  EncodingTest<int32_t>(100, 6000);
  EncodingTest<int64_t>(1000, 60000);

  EncodingTest<int8_t>(-1, -6);
  EncodingTest<int16_t>(-10, -60);
  EncodingTest<int32_t>(-100, -6000);
  EncodingTest<int64_t>(-1000, -60000);
}

TEST_F(BatchEncoderTest, PlusWorks) {
  auto pt = batch_encoder_.Encode<int64_t>(0, 0);
  auto buf = batch_encoder_.Serialize();
  BatchEncoder new_batch_encoder;
  new_batch_encoder.Deserialize(yasl::ByteContainerView(buf));

  int64_t sum_a = 0, sum_b = 0;
  for (int64_t n = 0; n > 0; n += INT64_MAX / 100000) {
    pt += batch_encoder_.Encode<int64_t>(-n, n);
    sum_a -= n;
    sum_b += n;
    EXPECT_EQ((new_batch_encoder.Get<int64_t, 0>(pt)), sum_a);
    EXPECT_EQ((new_batch_encoder.Get<int64_t, 1>(pt)), sum_b);
  }
}

TEST_F(BatchEncoderTest, PlusSubWorks) {
  auto pt = batch_encoder_.Encode<int64_t>(0, 0);
  int64_t sum = 0;
  int64_t sign = -1;
  for (int64_t n = 0; n > 0; n += INT64_MAX / 100000) {
    sign *= -1;
    pt += batch_encoder_.Encode<int64_t>(n * sign, n * sign);
    sum += n * sign;
    EXPECT_EQ((batch_encoder_.Get<int64_t, 0>(pt)), sum);
    EXPECT_EQ((batch_encoder_.Get<int64_t, 1>(pt)), sum);
  }
}

}  // namespace heu::lib::phe::test
