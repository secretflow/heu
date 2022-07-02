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

#include "heu/library/phe/encoding/plain_encoder.h"

#include "gtest/gtest.h"

namespace heu::lib::phe::test {

TEST(PlainEncoderTest, Basic) {
  PlainEncoder pe(1e10);

  auto pt1 = pe.Encode(0);
  EXPECT_EQ(pe.Decode<int>(pt1), 0);

  auto pt2 = pe.Encode(1000);
  EXPECT_EQ(pe.Decode<int64_t>(pt2), 1000);

  auto pt3 = pe.Encode(3.5);
  EXPECT_EQ(pe.Decode<double>(pt3), 3.5);

  PlainEncoder pe2;
  pe2.Deserialize(yasl::ByteContainerView(pe.Serialize()));
  auto pt4 = pt2 + pt3;
  EXPECT_EQ(pe2.Decode<double>(pt4), 1003.5);
  EXPECT_EQ(pe2.Decode<int64_t>(pt4), 1003);
}

TEST(PlainEncoderTest, Int128Works) {
  auto i64max = std::numeric_limits<int64_t>::max();
  int128_t i128 = static_cast<int128_t>(i64max) * i64max;

  PlainEncoder pe(1);
  auto pt = pe.Encode(i128);
  // make sure it is int128, much bigger than i64max
  ASSERT_GE(pt.BitCount(), 120);

  EXPECT_EQ(pe.Decode<int128_t>(pt), i128);
}

}  // namespace heu::lib::phe::test
