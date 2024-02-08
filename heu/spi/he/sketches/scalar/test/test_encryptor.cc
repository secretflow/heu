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

namespace heu::lib::spi::test {

class TestEncryptor : public ::testing::Test {
 protected:
  std::unique_ptr<Encryptor> enc_ = std::make_unique<DummyEncryptorImpl>();
};

TEST_F(TestEncryptor, TestEncScalar) {
  Item pt = {DummyPt("1"), ContentType::Plaintext};
  auto ct = enc_->Encrypt(pt);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "Enc(pt1)");

  pt = {DummyPt("2"), ContentType::Plaintext};
  ct.MarkAsPlaintext();
  enc_->Encrypt(pt, &ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "Enc(pt2)");

  ct = enc_->EncryptZero();
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "Enc(pt0)");

  pt = {DummyPt("4"), ContentType::Plaintext};
  ct = enc_->SemiEncrypt(pt);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "SemiEnc(pt4)");

  std::string audit;
  pt = {DummyPt("5"), ContentType::Plaintext};
  enc_->EncryptWithAudit(pt, &ct, &audit);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "Enc(pt5)");
  EXPECT_EQ(audit, "rand(pt5)");
}

TEST_F(TestEncryptor, TestEncVector) {
  auto pts = Item::Take(std::vector{DummyPt("1"), DummyPt("2"), DummyPt("3")},
                        ContentType::Plaintext);

  auto cts = enc_->Encrypt(pts);
  EXPECT_TRUE(cts.IsCiphertext());
  ExpectItemEq<DummyCt>(cts, {"Enc(pt1)", "Enc(pt2)", "Enc(pt3)"});

  pts = Item::Take(
      std::vector{DummyPt("1"), DummyPt("2"), DummyPt("3"), DummyPt("4")},
      ContentType::Plaintext);
  cts.MarkAsPlaintext();
  enc_->Encrypt(pts, &cts);
  EXPECT_TRUE(cts.IsCiphertext());
  ExpectItemEq<DummyCt>(cts, {"Enc(pt1)", "Enc(pt2)", "Enc(pt3)", "Enc(pt4)"});

  cts = enc_->EncryptZero(2);
  EXPECT_TRUE(cts.IsCiphertext());
  ExpectItemEq<DummyCt>(cts, {"Enc(pt0)", "Enc(pt0)"});

  pts = Item::Take(std::vector{DummyPt("1"), DummyPt("2"), DummyPt("3")},
                   ContentType::Plaintext);
  cts.MarkAsPlaintext();
  cts = enc_->SemiEncrypt(pts);
  EXPECT_TRUE(cts.IsCiphertext());
  ExpectItemEq<DummyCt>(cts, {"SemiEnc(pt1)", "SemiEnc(pt2)", "SemiEnc(pt3)"});

  std::string audit;
  Item out = Item::EmptyVector<DummyCt>();
  pts = Item::Take(std::vector{DummyPt("1"), DummyPt("2"), DummyPt("3")},
                   ContentType::Plaintext);
  enc_->EncryptWithAudit(pts, &out, &audit);
  EXPECT_TRUE(out.IsCiphertext());
  ExpectItemEq<DummyCt>(out, {"Enc(pt1)", "Enc(pt2)", "Enc(pt3)"});
  EXPECT_EQ(audit, "rand(pt1)||rand(pt2)||rand(pt3)");
}

}  // namespace heu::lib::spi::test
