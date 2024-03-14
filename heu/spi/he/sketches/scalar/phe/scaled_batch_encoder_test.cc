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

#include "heu/spi/he/sketches/scalar/phe/scaled_batch_encoder.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "absl/types/span.h"
#include "fmt/format.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "yacl/math/mpint/mp_int.h"

namespace heu::spi::test {

using ::yacl::math::MPInt;

class ScaledBatchEncoderTest : public testing::Test {};

TEST_F(ScaledBatchEncoderTest, SlotCountWorks) {
  auto be = std::make_unique<ScaledBatchEncoder<MPInt>>(1, 64, 1000);
  EXPECT_EQ(be->SlotCount(), 1);
  be = std::make_unique<ScaledBatchEncoder<MPInt>>(1, 128, 0);
  EXPECT_EQ(be->SlotCount(), 2);
  be = std::make_unique<ScaledBatchEncoder<MPInt>>(1, 128, 1);
  EXPECT_EQ(be->SlotCount(), 1);
  be = std::make_unique<ScaledBatchEncoder<MPInt>>(1, 129, 1);
  EXPECT_EQ(be->SlotCount(), 2);

  be = std::make_unique<ScaledBatchEncoder<MPInt>>(1, 256, 32);
  EXPECT_EQ(be->SlotCount(), 3);
  be = std::make_unique<ScaledBatchEncoder<MPInt>>(1, 255, 32);
  EXPECT_EQ(be->SlotCount(), 2);
  be = std::make_unique<ScaledBatchEncoder<MPInt>>(1, 257, 32);
  EXPECT_EQ(be->SlotCount(), 3);
}

template <class T>
void EncodingTest(std::shared_ptr<Encoder> be, absl::Span<const T> message) {
  auto pt = be->Encode(message);
  std::vector<T> out(be->CleartextCount(pt));
  be->Decode(pt, absl::MakeSpan(out));
  out.resize(message.size());
  EXPECT_THAT(out, testing::ElementsAreArray(message))
      << fmt::format("Encoder={}", be->ToString());
}

TEST_F(ScaledBatchEncoderTest, EncodingIntWorks) {
  const std::shared_ptr<Encoder> bes[] = {
      std::make_shared<ScaledBatchEncoder<MPInt>>(10, 2048, 0),    // no padding
      std::make_shared<ScaledBatchEncoder<MPInt>>(10, 2048, 1),    // 1 padding
      std::make_shared<ScaledBatchEncoder<MPInt>>(1e6, 64, 100),   // 1 slot
      std::make_shared<ScaledBatchEncoder<MPInt>>(1e6, 129, 1),    // 2 slot
      std::make_shared<ScaledBatchEncoder<MPInt>>(1e6, 2048, 32),  // regular
  };

  for (const auto &be : bes) {
    EncodingTest<int64_t>(be, {0});
    EncodingTest<int64_t>(be, {1});
    EncodingTest<int64_t>(be, {1, 2, 3});
    EncodingTest<int64_t>(be, {-1, -2, -3});
    EncodingTest<int64_t>(be, {0, 1, 10, 100});
    EncodingTest<int64_t>(be, {12, -34, 56, -78, 90});

    EncodingTest<uint64_t>(be, {0});
    EncodingTest<uint64_t>(be, {1});
    EncodingTest<uint64_t>(be, {1, 2, 3});
    EncodingTest<uint64_t>(be, {0, 1, 10, 100});
    EncodingTest<uint64_t>(be, {12, 34, 56, 78, 90});

    EncodingTest<double>(be, {0});
    EncodingTest<double>(be, {1});
    EncodingTest<double>(be, {1.1, 2.1, -3.1, 4.9, -5.9});
    EncodingTest<double>(be, {-1, -2, -3});
    EncodingTest<double>(be, {0, 1, 10, 100});
    EncodingTest<double>(be, {12, -34, 56, -78, 90});
  }
}

TEST_F(ScaledBatchEncoderTest, BitExamPass) {
  ScaledBatchEncoder<MPInt> be(1, 130, 1);  // no scale
  auto raw_pt = be.EncodeT((int64_t[]){-1, -1});
  // The 0~63, 65~129 bits should be 1; The 64 bit is padding
  for (int i = 0; i < 64; ++i) {
    EXPECT_EQ(raw_pt.GetBit(i), 1);
  }
  EXPECT_EQ(raw_pt.GetBit(64), 0);
  for (int i = 65; i < 129; ++i) {
    EXPECT_EQ(raw_pt.GetBit(i), 1);
  }
  EXPECT_EQ(raw_pt.GetBit(129), 0);
}

}  // namespace heu::spi::test
