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
#include <string>
#include <tuple>
#include <vector>

#include "fmt/ranges.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "heu/spi/auto_test/tool.h"
#include "heu/spi/he/he_kit.h"

namespace heu::spi::test {

class ArithmeticTest : public testing::TestWithParam<std::shared_ptr<HeKit>> {
 protected:
  void SetUp() override {
    kit_ = GetParam();
    fmt::println("Testing {}", *kit_);

    itool_ = kit_->GetItemTool();
    enc_ = kit_->GetEncryptor();
    eval_ = kit_->GetWordEvaluator();
    dec_ = kit_->GetDecryptor();
  }

  std::shared_ptr<Encoder> TryGetEncoder(std::string method, int64_t scale) {
    if (kit_->GetFeatureSet() == FeatureSet::WordFHE) {
      SPDLOG_WARN("BFV/BGV-like schemas do not support scale, ignore the arg");
      return kit_->GetEncoder(ArgEncodingMethod = method);
    }

    return kit_->GetEncoder(ArgEncodingMethod = method, ArgScale = scale);
  }

 protected:
  std::shared_ptr<HeKit> kit_;

  std::shared_ptr<ItemTool> itool_;
  std::shared_ptr<Encryptor> enc_;
  std::shared_ptr<WordEvaluator> eval_;
  std::shared_ptr<Decryptor> dec_;
};

INSTANTIATE_TEST_SUITE_P(HeCollection, ArithmeticTest,
                         SelectHeKitsForTest({FeatureSet::AdditivePHE,
                                              FeatureSet::WordFHE}),
                         GenTestName<ArithmeticTest>);

TEST_P(ArithmeticTest, EncryptZeroWorks) {
  //== single plaintext case ==//
  auto edr = kit_->GetEncoder(ArgEncodingMethod = "plain");

  auto ct0 = enc_->EncryptZero();
  auto plain = dec_->Decrypt(ct0);
  ASSERT_EQ(edr->DecodeScalarInt64(plain), 0);

  eval_->AddInplace(&ct0, enc_->EncryptZero());
  plain = dec_->Decrypt(ct0);
  ASSERT_EQ(edr->DecodeScalarInt64(plain), 0);

  eval_->SubInplace(&ct0, enc_->EncryptZero());
  plain = dec_->Decrypt(ct0);
  ASSERT_EQ(edr->DecodeScalarInt64(plain), 0);

  auto p = eval_->Sub(edr->Encode((int64_t)123), ct0);
  ASSERT_EQ(edr->DecodeScalarInt64(dec_->Decrypt(p)), 123);

  // 0 * 0
  eval_->MulInplace(&ct0, edr->Encode((int64_t)0));
  ASSERT_EQ(edr->DecodeScalarInt64(dec_->Decrypt(ct0)), 0);

  eval_->MulInplace(&ct0, edr->Encode((int64_t)123456));
  ASSERT_EQ(edr->DecodeScalarInt64(dec_->Decrypt(ct0)), 0);

  eval_->MulInplace(&ct0, edr->Encode((int64_t)-123456));
  ASSERT_EQ(edr->DecodeScalarInt64(dec_->Decrypt(ct0)), 0);

  eval_->NegateInplace(&ct0);
  ASSERT_EQ(edr->DecodeScalarInt64(dec_->Decrypt(ct0)), 0);

  //== multi plaintexts case ==//
  ct0 = enc_->EncryptZero(10);
  EXPECT_EQ(kit_->GetItemTool()->ItemSize(ct0), 10);

  std::vector<int64_t> zeros(10);
  auto pt0 = edr->Encode(absl::MakeSpan(zeros));
  eval_->AddInplace(&ct0, pt0);
  auto res = edr->DecodeInt64(dec_->Decrypt(ct0));
  EXPECT_EQ(res.size(), 10);
  EXPECT_THAT(res, testing::Each(0));

  eval_->AddInplace(&ct0, enc_->Encrypt(pt0));
  res = edr->DecodeInt64(dec_->Decrypt(ct0));
  EXPECT_EQ(res.size(), 10);
  EXPECT_THAT(res, testing::Each(0));
}

TEST_P(ArithmeticTest, TestEncDecScalar) {
  auto edr = TryGetEncoder("plain", 1);

  Item pt = edr->Encode((int64_t)1);
  EXPECT_TRUE(pt.IsPlaintext());
  EXPECT_EQ(edr->CleartextCount(pt), 1);
  EXPECT_EQ(kit_->GetItemTool()->ItemSize(pt), 1);
  auto ct = enc_->Encrypt(pt);
  EXPECT_TRUE(ct.IsCiphertext());
  ASSERT_EQ(edr->DecodeScalarInt64(dec_->Decrypt(ct)), 1);

  pt = edr->Encode((int64_t)-1);
  enc_->Encrypt(pt, &ct);
  EXPECT_TRUE(ct.IsCiphertext());
  dec_->Decrypt(ct, &pt);
  ASSERT_EQ(edr->DecodeScalarInt64(pt), -1);

  pt = edr->Encode((int64_t)1234);
  ct = enc_->SemiEncrypt(pt);
  EXPECT_TRUE(ct.IsCiphertext());
  ASSERT_EQ(edr->DecodeScalarInt64(dec_->Decrypt(ct)), 1234);

  std::string audit;
  pt = edr->Encode((int64_t)-1234);
  enc_->EncryptWithAudit(pt, &ct, &audit);
  EXPECT_TRUE(ct.IsCiphertext());
  ASSERT_EQ(edr->DecodeScalarInt64(dec_->Decrypt(ct)), -1234);
  // EXPECT_THAT(audit, testing::HasSubstr("-1234"));
}

TEST_P(ArithmeticTest, TestEncDecVector) {
  auto edr = TryGetEncoder("batch", 10);
  fmt::print("edr info: {}\n", edr->ToString());

  if (kit_->GetFeatureSet() == FeatureSet::WordFHE) {
    GTEST_SKIP() << fmt::format("{} do not support float number, skip",
                                kit_->GetSchema());
  }

  // small case
  std::vector<double> vec(10);
  for (size_t i = 0; i < vec.size(); ++i) {
    vec[i] = i + 0.1 - vec.size() / 2;
  }
  fmt::print("vec is {}\n", vec);
  EXPECT_EQ(vec[0], -4.9);
  EXPECT_EQ(vec[9], 4.1);

  auto pts = edr->Encode(vec);
  EXPECT_TRUE(pts.IsPlaintext());
  auto cts = enc_->Encrypt(pts);
  EXPECT_TRUE(cts.IsCiphertext());

  auto out = edr->DecodeDouble(dec_->Decrypt(cts));
  out.resize(vec.size());  // shrink size
  EXPECT_THAT(out, testing::Pointwise(testing::FloatEq(), vec));

  // big case, cleartexts will encode to multiple plaintexts
  vec.resize(10000);
  for (size_t i = 0; i < vec.size(); ++i) {
    vec[i] = i + 0.9 - vec.size() / 2;
  }
  EXPECT_DOUBLE_EQ(vec[0], -4999.1);
  EXPECT_DOUBLE_EQ(vec[9999], 4999.9);

  pts = edr->Encode(vec);
  EXPECT_GE(edr->CleartextCount(pts), vec.size());
  EXPECT_LE(kit_->GetItemTool()->ItemSize(pts), vec.size());
  EXPECT_EQ(kit_->GetItemTool()->ItemSize(pts),
            edr->CleartextCount(pts) / edr->SlotCount());
  enc_->Encrypt(pts, &cts);
  EXPECT_TRUE(cts.IsCiphertext());
  pts = Item(0, ContentType::Others);
  dec_->Decrypt(cts, &pts);
  EXPECT_TRUE(pts.IsPlaintext());
  EXPECT_GE(edr->CleartextCount(pts), vec.size());
  out.resize(edr->CleartextCount(pts));
  edr->Decode(pts, absl::MakeSpan(out));
  out.resize(vec.size());
  EXPECT_THAT(out, testing::Pointwise(testing::FloatEq(), vec));
}

TEST_P(ArithmeticTest, TestEvaluate) {
  auto edr = TryGetEncoder("plain", 1);

  std::vector<int64_t> pts1_vec = {0, 1, -1, 123, -456, 789};
  const auto pts1 = edr->Encode(pts1_vec);
  EXPECT_EQ(kit_->GetItemTool()->ItemSize(pts1), 6);
  const auto cts1 = enc_->Encrypt(pts1);
  std::vector<int64_t> pts2_vec = {0, 1, 1, -124, -1, 96};
  const auto pts2 = edr->Encode(pts2_vec);
  EXPECT_EQ(kit_->GetItemTool()->ItemSize(pts2), 6);
  const auto cts2 = enc_->Encrypt(pts2);

  // test equal
  EXPECT_TRUE(itool_->Equal(pts1, pts1));
  EXPECT_FALSE(itool_->Equal(pts1, pts2));
  EXPECT_FALSE(itool_->Equal(pts1, cts1));
  EXPECT_FALSE(itool_->Equal(cts1, cts2));
  EXPECT_TRUE(itool_->Equal(cts2, cts2));
  EXPECT_TRUE(itool_->Equal(pts1, edr->Encode(pts1_vec)));
  EXPECT_FALSE(
      itool_->Equal(pts1, edr->Encode((int64_t[]){0, 1, -1, 123, -456, -789})));

  // negate
  Item res = eval_->Negate(pts1);
  EXPECT_THAT(edr->DecodeInt64(res),
              testing::ElementsAre(0, -1, 1, -123, 456, -789));
  res = eval_->Negate(cts1);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, -1, 1, -123, 456, -789));

  // add
  res = eval_->Add(cts1, cts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, 2, 0, -1, -457, 885));
  res = eval_->Add(cts1, pts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, 2, 0, -1, -457, 885));
  res = eval_->Add(pts1, cts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, 2, 0, -1, -457, 885));
  res = eval_->Add(pts1, pts2);
  EXPECT_THAT(edr->DecodeInt64(res),
              testing::ElementsAre(0, 2, 0, -1, -457, 885));

  // sub
  res = eval_->Sub(cts1, cts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, 0, -2, 247, -455, 693));
  res = eval_->Sub(cts1, pts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, 0, -2, 247, -455, 693));
  res = eval_->Sub(pts1, cts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, 0, -2, 247, -455, 693));
  res = eval_->Sub(pts1, pts2);
  EXPECT_THAT(edr->DecodeInt64(res),
              testing::ElementsAre(0, 0, -2, 247, -455, 693));

  // mul
  res = eval_->Mul(cts1, pts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, 1, -1, -15252, 456, 75744));
  res = eval_->Mul(pts1, cts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, 1, -1, -15252, 456, 75744));
  res = eval_->Mul(pts1, pts2);
  EXPECT_THAT(edr->DecodeInt64(res),
              testing::ElementsAre(0, 1, -1, -15252, 456, 75744));

  // square
  res = eval_->Square(pts2);
  EXPECT_THAT(edr->DecodeInt64(res),
              testing::ElementsAre(0, 1, 1, 15376, 1, 9216));

  // pow
  const auto pts_exp = edr->Encode((int64_t[]){-10, -1, 1, 3, 11});
  res = eval_->Pow(pts_exp, 1);
  EXPECT_THAT(edr->DecodeInt64(res), testing::ElementsAre(-10, -1, 1, 3, 11));
  res = eval_->Pow(pts_exp, 3);
  EXPECT_THAT(edr->DecodeInt64(res),
              testing::ElementsAre(-1000, -1, 1, 27, 1331));

  //== Test FHE only functions below ==//

  if (kit_->GetFeatureSet() == FeatureSet::AdditivePHE) {
    GTEST_SKIP() << fmt::format("{} do not support ciphertext mul/pow, skip",
                                kit_->GetSchema());
  }

  // mul
  res = eval_->Mul(cts1, cts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, 1, -1, -15252, 456, 75744));

  // square
  res = eval_->Square(cts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(0, 1, 1, 15376, 1, 9216));

  // pow
  const auto cts_exp = enc_->Encrypt(pts_exp);
  res = eval_->Pow(cts_exp, 1);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(-10, -1, 1, 3, 11));
  res = eval_->Pow(cts_exp, 3);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              testing::ElementsAre(-1000, -1, 1, 27, 1331));
}

TEST_P(ArithmeticTest, TestEvaluateInplace) {
  auto edr = TryGetEncoder("plain", 1);

  std::vector<int64_t> pts1_vec = {1, -1, 0, 2, 3, 5, 7, 11, 13, 17, -19};
  std::vector<int64_t> pts2_vec = {1, 3, 7, -1, -3, -5, 19, -13, 2, 8, 8};
  const auto pts2 = edr->Encode(pts2_vec);
  const auto cts2 = enc_->Encrypt(pts2);

  // negate
  auto pts1 = edr->Encode(pts1_vec);
  auto cts1 = enc_->Encrypt(pts1);
  eval_->NegateInplace(&pts1);
  EXPECT_THAT(
      edr->DecodeInt64(pts1),
      testing::ElementsAre(-1, 1, 0, -2, -3, -5, -7, -11, -13, -17, 19));
  eval_->NegateInplace(&cts1);
  EXPECT_THAT(
      edr->DecodeInt64(dec_->Decrypt(cts1)),
      testing::ElementsAre(-1, 1, 0, -2, -3, -5, -7, -11, -13, -17, 19));

  // add
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->AddInplace(&cts1, cts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(cts1)),
              testing::ElementsAre(2, 2, 7, 1, 0, 0, 26, -2, 15, 25, -11));

  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->AddInplace(&cts1, pts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(cts1)),
              testing::ElementsAre(2, 2, 7, 1, 0, 0, 26, -2, 15, 25, -11));

  // sub
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->SubInplace(&cts1, cts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(cts1)),
              testing::ElementsAre(0, -4, -7, 3, 6, 10, -12, 24, 11, 9, -27));

  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->SubInplace(&cts1, pts2);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(cts1)),
              testing::ElementsAre(0, -4, -7, 3, 6, 10, -12, 24, 11, 9, -27));

  // mul
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->MulInplace(&cts1, pts2);
  EXPECT_THAT(
      edr->DecodeInt64(dec_->Decrypt(cts1)),
      testing::ElementsAre(1, -3, 0, -2, -9, -25, 133, -143, 26, 136, -152));

  // square
  pts1 = edr->Encode(pts1_vec);
  eval_->SquareInplace(&pts1);
  EXPECT_THAT(edr->DecodeInt64(pts1),
              testing::ElementsAre(1, 1, 0, 4, 9, 25, 49, 121, 169, 289, 361));

  // pow
  auto pts_exp = edr->Encode(pts2_vec);
  pts_exp = edr->Encode(pts2_vec);
  eval_->PowInplace(&pts_exp, 1);
  EXPECT_THAT(edr->DecodeInt64(pts_exp),
              testing::ElementsAre(1, 3, 7, -1, -3, -5, 19, -13, 2, 8, 8));
  pts_exp = edr->Encode(pts2_vec);
  eval_->PowInplace(&pts_exp, 3);
  EXPECT_THAT(edr->DecodeInt64(pts_exp),
              testing::ElementsAre(1, 27, 343, -1, -27, -125, 6859, -2197, 8,
                                   512, 512));

  // ct randomize
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->Randomize(&cts1);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(cts1)),
              testing::ElementsAre(1, -1, 0, 2, 3, 5, 7, 11, 13, 17, -19));

  //== Test FHE only functions below ==//

  if (kit_->GetFeatureSet() == FeatureSet::AdditivePHE) {
    GTEST_SKIP() << fmt::format(
        "{} do not support ciphertext mul/square/pow, skip", kit_->GetSchema());
  }

  // mul
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->MulInplace(&cts1, cts2);
  EXPECT_THAT(
      edr->DecodeInt64(dec_->Decrypt(cts1)),
      testing::ElementsAre(1, -3, 0, -2, -9, -25, 133, -143, 26, 136, -152));

  // square
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->SquareInplace(&cts1);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(cts1)),
              testing::ElementsAre(1, 1, 0, 4, 9, 25, 49, 121, 169, 289, 361));

  // pow
  pts_exp = edr->Encode(pts2_vec);
  auto cts_exp = enc_->Encrypt(pts_exp);
  eval_->PowInplace(&cts_exp, 1);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(cts_exp)),
              testing::ElementsAre(1, 3, 7, -1, -3, -5, 19, -13, 2, 8, 8));
  enc_->Encrypt(pts_exp, &cts_exp);
  eval_->PowInplace(&cts_exp, 3);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(cts_exp)),
              testing::ElementsAre(1, 27, 343, -1, -27, -125, 6859, -2197, 8,
                                   512, 512));
}

TEST_P(ArithmeticTest, TestSwapRows) {
  if (kit_->GetFeatureSet() == FeatureSet::AdditivePHE) {
    GTEST_SKIP();
  }

  auto edr = TryGetEncoder("batch", 1);
  std::vector<int64_t> pts1_vec = {0, 1, -1, 123, -456, 789};
  const auto pts1 = edr->Encode(pts1_vec);
  auto cts1 = enc_->Encrypt(pts1);

  // swap row
  eval_->SwapRowsInplace(&cts1);
  auto res_vec = edr->DecodeInt64(dec_->Decrypt(cts1));
  // line 1 is all zero
  EXPECT_THAT(absl::MakeSpan(res_vec.data(), edr->SlotCount() / 2),
              testing::Each(testing::Eq(0)));
  // test line 2
  EXPECT_THAT(absl::MakeSpan(res_vec.data() + edr->SlotCount() / 2,
                             edr->SlotCount() / 2),
              BeginWith<std::vector<int64_t>>({0, 1, -1, 123, -456, 789}));

  // swap row back
  auto res = eval_->SwapRows(cts1);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(res)),
              BeginWith<std::vector<int64_t>>({0, 1, -1, 123, -456, 789}));
}

}  // namespace heu::spi::test
