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

#include <memory>

#include "gtest/gtest.h"

#include "heu/spi/he/sketches/scalar/test/dummy_ops.h"

namespace heu::spi::test {

class TestDecryptor : public ::testing::Test {
 protected:
  std::unique_ptr<Decryptor> dec_ = std::make_unique<DummyDecryptorImpl>();
};

TEST_F(TestDecryptor, TestDec) {
  Item ct = {DummyCt("1"), ContentType::Ciphertext};
  auto pt = dec_->Decrypt(ct);
  EXPECT_TRUE(pt.IsPlaintext());
  EXPECT_EQ(pt.As<DummyPt>().Id(), "Dec(ct1)");

  ct = {DummyCt("2"), ContentType::Ciphertext};
  pt.MarkAsCiphertext();
  dec_->Decrypt(ct, &pt);
  EXPECT_TRUE(pt.IsPlaintext());
  EXPECT_EQ(pt.As<DummyPt>().Id(), "Dec(ct2)");

  // vector call
  auto cts = Item::Take(std::vector{DummyCt("1"), DummyCt("2"), DummyCt("3")},
                        ContentType::Ciphertext);
  auto pts = dec_->Decrypt(cts);
  EXPECT_FALSE(pts.IsCiphertext());
  ExpectItemEq<DummyPt>(pts, {"Dec(ct1)", "Dec(ct2)", "Dec(ct3)"});

  pts = Item::EmptyVector<DummyPt>();
  dec_->Decrypt(cts, &pts);
  EXPECT_TRUE(pts.IsPlaintext());
  ExpectItemEq<DummyPt>(pts, {"Dec(ct1)", "Dec(ct2)", "Dec(ct3)"});
}

}  // namespace heu::spi::test
