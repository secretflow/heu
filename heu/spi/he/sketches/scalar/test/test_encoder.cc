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

#include "gtest/gtest.h"

#include "heu/spi/he/sketches/scalar/test/dummy_hekit.h"

namespace heu::lib::spi::test {

class TestEncoders : public ::testing::Test {
 protected:
  std::unique_ptr<HeKit> kit_ = std::make_unique<DummyHeKit>();
};

template <typename T>
void CheckEq(std::vector<T> a, std::vector<T> b) {
  EXPECT_EQ(a.size(), b.size());
  for (size_t i = 0; i < a.size(); ++i) {
    EXPECT_EQ(a[i], b[i]);
  }
}

TEST_F(TestEncoders, PlainWorks) {
  auto pe = kit_->GetEncoder();

  EXPECT_EQ(pe->ToString(), "DummyPlainEncoder");
  EXPECT_EQ(pe->FromString("haha"), DummyPt("haha"));
  EXPECT_EQ(pe->SlotCount(), 1);

  auto pt1 = pe->Encode((int64_t[]){-1, -2, -3});
  EXPECT_EQ(pe->GetCleartextCount(pt1), 3);
  EXPECT_EQ(pt1.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt1, {"Encode(-1)", "Encode(-2)", "Encode(-3)"});

  auto pt2 = pe->Encode((uint64_t[]){1, 2, 3});
  EXPECT_EQ(pe->GetCleartextCount(pt2), 3);
  EXPECT_EQ(pt2.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt2, {"Encode(1)", "Encode(2)", "Encode(3)"});

  auto pt3 = pe->Encode((double[]){1.1, 2.1, 3.1});
  EXPECT_EQ(pe->GetCleartextCount(pt3), 3);
  EXPECT_EQ(pt3.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt3, {"Encode(1.1)", "Encode(2.1)", "Encode(3.1)"});

  using namespace std::complex_literals;
  auto pt4 = pe->Encode((std::complex<double>[]){1.0 + 2i, 2.0 + 2i, 3.0 + 2i});
  EXPECT_EQ(pe->GetCleartextCount(pt4), 3);
  EXPECT_EQ(pt4.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt4,
                        {"Encode(1 + 2i)", "Encode(2 + 2i)", "Encode(3 + 2i)"});

  std::vector<int64_t> out1(3);
  pe->Decode(pt1, absl::MakeSpan(out1));
  CheckEq(out1, {44, 44, 44});
  std::vector<uint64_t> out2(3);
  pe->Decode(pt2, absl::MakeSpan(out2));
  CheckEq(out2, {48, 48, 48});
  std::vector<double> out3(3);
  pe->Decode(pt3, absl::MakeSpan(out3));
  CheckEq(out3, {52, 52, 52});
  std::vector<std::complex<double>> out4(3);
  pe->Decode(pt4, absl::MakeSpan(out4));
  CheckEq(out4, {57i, 57i, 57i});

  auto v1 = pe->DecodeInt64(pt1);
  CheckEq(v1, {44, 44, 44});
  auto v2 = pe->DecodeUint64(pt2);
  CheckEq(v2, {48, 48, 48});
  auto v3 = pe->DecodeDouble(pt3);
  CheckEq(v3, {52, 52, 52});
  auto v4 = pe->DecodeComplex(pt4);
  CheckEq(v4, {57i, 57i, 57i});

  // scalar encode/decode
  pt1 = pe->EncodeScalar((int64_t)-123);
  EXPECT_EQ(pt1, DummyPt("Encode(-123)"));
  EXPECT_EQ(pt1.GetContentType(), ContentType::Plaintext);
  pt2 = pe->EncodeScalar((uint64_t)123);
  EXPECT_EQ(pt2, DummyPt("Encode(123)"));
  EXPECT_EQ(pt2.GetContentType(), ContentType::Plaintext);
  pt3 = pe->EncodeScalar((double)123.4);
  EXPECT_EQ(pt3, DummyPt("Encode(123.4)"));
  EXPECT_EQ(pt3.GetContentType(), ContentType::Plaintext);
  pt4 = pe->EncodeScalar(1.2 + 3i);
  EXPECT_EQ(pt4, DummyPt("Encode(1.2 + 3i)"));
  EXPECT_EQ(pt4.GetContentType(), ContentType::Plaintext);

  EXPECT_EQ(pe->DecodeScalarInt64(pt1), 44);
  EXPECT_EQ(pe->DecodeScalarUint64(pt2), 48);
  EXPECT_EQ(pe->DecodeScalarDouble(pt3), 52);
  EXPECT_EQ(pe->DecodeScalarComplex(pt4), 57i);
}

TEST_F(TestEncoders, BatchWorks) {
  auto pe = kit_->GetEncoder(ArgEncoder = "Batch", ArgSlot = 2);

  EXPECT_EQ(pe->ToString(), "DummyBatchEncoder");
  EXPECT_EQ(pe->FromString("haha"), DummyPt("haha"));
  EXPECT_EQ(pe->SlotCount(), 2);

  auto pt1 = pe->Encode((int64_t[]){-1, -2, -3});
  EXPECT_EQ(pe->GetCleartextCount(pt1), 4);  // 2 pt, each has 2 slots
  EXPECT_EQ(pt1.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt1, {"Encode(-1, -2)", "Encode(-3)"});

  auto pt2 = pe->Encode((uint64_t[]){1, 2, 3});
  EXPECT_EQ(pe->GetCleartextCount(pt2), 4);
  EXPECT_EQ(pt2.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt2, {"Encode(1, 2)", "Encode(3)"});

  auto pt3 = pe->Encode((double[]){1.1, 2.1, 3.1});
  EXPECT_EQ(pe->GetCleartextCount(pt3), 4);
  EXPECT_EQ(pt3.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt3, {"Encode(1.1, 2.1)", "Encode(3.1)"});

  using namespace std::complex_literals;
  auto pt4 = pe->Encode((std::complex<double>[]){1.0 + 2i, 2.0 + 2i, 3.0 + 2i});
  EXPECT_EQ(pe->GetCleartextCount(pt4), 4);
  EXPECT_EQ(pt4.GetContentType(), ContentType::Plaintext);
  ExpectItemEq<DummyPt>(pt4, {"Encode(complex2)", "Encode(complex1)"});

  std::vector<int64_t> out1(4);
  pe->Decode(pt1, absl::MakeSpan(out1));
  CheckEq(out1, {96, 97, 96, 97});
  std::vector<uint64_t> out2(4);
  pe->Decode(pt2, absl::MakeSpan(out2));
  CheckEq(out2, {103, 104, 103, 104});
  std::vector<double> out3(4);
  pe->Decode(pt3, absl::MakeSpan(out3));
  CheckEq(out3, {110, 111, 110, 111});
  std::vector<std::complex<double>> out4(4);
  pe->Decode(pt4, absl::MakeSpan(out4));
  CheckEq(out4, {118, 119, 118, 119});

  auto v1 = pe->DecodeInt64(pt1);
  CheckEq(v1, {96, 97, 96, 97});
  auto v2 = pe->DecodeUint64(pt2);
  CheckEq(v2, {103, 104, 103, 104});
  auto v3 = pe->DecodeDouble(pt3);
  CheckEq(v3, {110, 111, 110, 111});
  auto v4 = pe->DecodeComplex(pt4);
  CheckEq(v4, {118, 119, 118, 119});
}

}  // namespace heu::lib::spi::test
