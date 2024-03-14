// Copyright 2024 Ant Group Co., Ltd.
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

#include <complex>
#include <memory>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "heu/spi/he/sketches/scalar/test/dummy_hekit.h"

namespace heu::spi::test {

class TestEncoders : public ::testing::Test {
 protected:
  std::unique_ptr<HeKit> kit_ = std::make_unique<DummyHeKit>();
};

TEST_F(TestEncoders, PlainWorks) {
  auto pe = kit_->GetEncoder();

  EXPECT_EQ(pe->ToString(), "DummyPlainEncoder");
  EXPECT_EQ(pe->FromString("haha"), DummyPt("haha"));
  EXPECT_EQ(pe->SlotCount(), 1);

  auto pt1 = pe->Encode((int64_t[]){-1, -2, -3});
  EXPECT_EQ(pe->CleartextCount(pt1), 3);
  EXPECT_EQ(pt1.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt1, {"Encode(-1)", "Encode(-2)", "Encode(-3)"});

  auto pt2 = pe->Encode((uint64_t[]){1, 2, 3});
  EXPECT_EQ(pe->CleartextCount(pt2), 3);
  EXPECT_EQ(pt2.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt2, {"Encode(1)", "Encode(2)", "Encode(3)"});

  auto pt3 = pe->Encode((double[]){1.1, 2.1, 3.1});
  EXPECT_EQ(pe->CleartextCount(pt3), 3);
  EXPECT_EQ(pt3.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt3, {"Encode(1.1)", "Encode(2.1)", "Encode(3.1)"});

  using namespace std::complex_literals;
  auto pt4 = pe->Encode((std::complex<double>[]){1.0 + 2i, 2.0 + 2i, 3.0 + 2i});
  EXPECT_EQ(pe->CleartextCount(pt4), 3);
  EXPECT_EQ(pt4.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt4,
                        {"Encode(1 + 2i)", "Encode(2 + 2i)", "Encode(3 + 2i)"});

  std::vector<int64_t> out1(3);
  pe->Decode(pt1, absl::MakeSpan(out1));
  EXPECT_THAT(out1, testing::ElementsAre(44, 44, 44));
  std::vector<uint64_t> out2(3);
  pe->Decode(pt2, absl::MakeSpan(out2));
  EXPECT_THAT(out2, testing::ElementsAre(48, 48, 48));
  std::vector<double> out3(3);
  pe->Decode(pt3, absl::MakeSpan(out3));
  EXPECT_THAT(out3, testing::ElementsAre(52, 52, 52));
  std::vector<std::complex<double>> out4(3);
  pe->Decode(pt4, absl::MakeSpan(out4));
  EXPECT_THAT(out4, testing::ElementsAre(57i, 57i, 57i));

  auto v1 = pe->DecodeInt64(pt1);
  EXPECT_THAT(v1, testing::ElementsAre(44, 44, 44));
  auto v2 = pe->DecodeUint64(pt2);
  EXPECT_THAT(v2, testing::ElementsAre(48, 48, 48));
  auto v3 = pe->DecodeDouble(pt3);
  EXPECT_THAT(v3, testing::ElementsAre(52, 52, 52));
  auto v4 = pe->DecodeComplex(pt4);
  EXPECT_THAT(v4, testing::ElementsAre(57i, 57i, 57i));

  // scalar encode/decode
  pt1 = pe->Encode((int64_t)-123);
  EXPECT_EQ(pt1, DummyPt("Encode(-123)"));
  EXPECT_EQ(pt1.GetContentType(), ContentType::Plaintext);
  pt2 = pe->Encode((uint64_t)123);
  EXPECT_EQ(pt2, DummyPt("Encode(123)"));
  EXPECT_EQ(pt2.GetContentType(), ContentType::Plaintext);
  pt3 = pe->Encode((double)123.4);
  EXPECT_EQ(pt3, DummyPt("Encode(123.4)"));
  EXPECT_EQ(pt3.GetContentType(), ContentType::Plaintext);
  pt4 = pe->Encode(1.2 + 3i);
  EXPECT_EQ(pt4, DummyPt("Encode(1.2 + 3i)"));
  EXPECT_EQ(pt4.GetContentType(), ContentType::Plaintext);

  EXPECT_EQ(pe->DecodeScalarInt64(pt1), 44);
  EXPECT_EQ(pe->DecodeScalarUint64(pt2), 48);
  EXPECT_EQ(pe->DecodeScalarDouble(pt3), 52);
  EXPECT_EQ(pe->DecodeScalarComplex(pt4), 57i);
}

TEST_F(TestEncoders, BatchWorks) {
  auto be = kit_->GetEncoder(ArgEncodingMethod = "Batch", ArgSlot = 2);

  EXPECT_EQ(be->ToString(), "DummyBatchEncoder");
  EXPECT_EQ(be->FromString("haha"), DummyPt("haha"));
  EXPECT_EQ(be->SlotCount(), 2);

  std::vector<int64_t> ct0;
  // throw exception: Input message is empty, nothing to encode
  EXPECT_ANY_THROW(be->Encode(ct0));

  auto pt1 = be->Encode((int64_t[]){-1, -2, -3});
  EXPECT_EQ(be->CleartextCount(pt1), 4);  // 2 pt, each has 2 slots
  EXPECT_EQ(pt1.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt1, {"Encode(-1, -2)", "Encode(-3)"});

  auto pt2 = be->Encode((uint64_t[]){1, 2, 3});
  EXPECT_EQ(be->CleartextCount(pt2), 4);
  EXPECT_EQ(pt2.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt2, {"Encode(1, 2)", "Encode(3)"});

  auto pt3 = be->Encode((double[]){1.1, 2.1, 3.1});
  EXPECT_EQ(be->CleartextCount(pt3), 4);
  EXPECT_EQ(pt3.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt3, {"Encode(1.1, 2.1)", "Encode(3.1)"});

  using namespace std::complex_literals;
  auto pt4 = be->Encode((std::complex<double>[]){1.0 + 2i, 2.0 + 2i, 3.0 + 2i});
  EXPECT_EQ(be->CleartextCount(pt4), 4);
  EXPECT_EQ(pt4.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt4, {"Encode(complex2)", "Encode(complex1)"});

  // test batch decode
  std::vector<int64_t> out1(4);
  be->Decode(pt1, absl::MakeSpan(out1));
  EXPECT_THAT(out1, testing::ElementsAre(96, 97, 96, 97));
  std::vector<uint64_t> out2(4);
  be->Decode(pt2, absl::MakeSpan(out2));
  EXPECT_THAT(out2, testing::ElementsAre(103, 104, 103, 104));
  std::vector<double> out3(4);
  be->Decode(pt3, absl::MakeSpan(out3));
  EXPECT_THAT(out3, testing::ElementsAre(110, 111, 110, 111));
  std::vector<std::complex<double>> out4(4);
  be->Decode(pt4, absl::MakeSpan(out4));
  EXPECT_THAT(out4, testing::ElementsAre(118, 119, 118, 119));

  auto v1 = be->DecodeInt64(pt1);
  EXPECT_THAT(v1, testing::ElementsAre(96, 97, 96, 97));
  auto v2 = be->DecodeUint64(pt2);
  EXPECT_THAT(v2, testing::ElementsAre(103, 104, 103, 104));
  auto v3 = be->DecodeDouble(pt3);
  EXPECT_THAT(v3, testing::ElementsAre(110, 111, 110, 111));
  auto v4 = be->DecodeComplex(pt4);
  EXPECT_THAT(v4, testing::ElementsAre(118, 119, 118, 119));

  // test encode scalar
  pt1 = be->Encode((int64_t)-1);
  EXPECT_EQ(be->CleartextCount(pt1), 2);  // plaintext has two slots
  ExpectItemEq<DummyPt>(pt1, {"Encode(-1, -1)"});

  pt2 = be->Encode((uint64_t){1});
  ExpectItemEq<DummyPt>(pt2, {"Encode(1, 1)"});

  pt3 = be->Encode((double){1.1});
  ExpectItemEq<DummyPt>(pt3, {"Encode(1.1, 1.1)"});

  pt4 = be->Encode((std::complex<double>){1.0 + 2i});
  ExpectItemEq<DummyPt>(pt4, {"Encode(complex2)"});

  // Batch encoder cannot decode scalars
  EXPECT_ANY_THROW(be->DecodeScalarInt64(pt1));
  EXPECT_ANY_THROW(be->DecodeScalarUint64(pt1));
  EXPECT_ANY_THROW(be->DecodeScalarDouble(pt1));
  EXPECT_ANY_THROW(be->DecodeScalarComplex(pt1));
}

}  // namespace heu::spi::test
