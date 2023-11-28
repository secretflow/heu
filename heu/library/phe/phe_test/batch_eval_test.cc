// Copyright 2023 Ant Group Co., Ltd.
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

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "heu/library/phe/encoding/encoding.h"
#include "heu/library/phe/phe.h"

namespace heu::lib::phe::test {

class BatchEvalTest : public ::testing::TestWithParam<SchemaType> {
 protected:
  void SetUp() override {
    auto sk_str = he_kit_.GetSecretKey()->ToString();
    EXPECT_GT(sk_str.length(), 30) << sk_str;
    auto pk_str = he_kit_.GetPublicKey()->ToString();
    EXPECT_GT(pk_str.length(), 30) << pk_str;
  }

 protected:
  HeKit he_kit_ = HeKit(GetParam());
};

INSTANTIATE_TEST_SUITE_P(Schema, BatchEvalTest,
                         ::testing::ValuesIn(GetAllSchema()));

// test batch encoding
TEST_P(BatchEvalTest, BatchEncoding) {
  if (GetParam() == SchemaType::ElGamal) {
    GTEST_SKIP() << "Plaintext range is not enough, Skip ElGamal";
  }
  if (GetParam() == SchemaType::DGK) {
    GTEST_SKIP() << "Plaintext range is not enough, Skip DGK";
  }
  auto encryptor = he_kit_.GetEncryptor();
  auto evaluator = he_kit_.GetEvaluator();
  auto decryptor = he_kit_.GetDecryptor();
  BatchEncoder batch_encoder(GetParam());

  auto m0 = batch_encoder.Encode<int64_t>(-123, 123);
  Ciphertext ct0 = encryptor->Encrypt(m0);

  Ciphertext res = evaluator->Add(ct0, batch_encoder.Encode<int64_t>(23, 23));
  Plaintext plain = decryptor->Decrypt(res);
  EXPECT_EQ((batch_encoder.Decode<int64_t, 0>(plain)), -123 + 23);
  EXPECT_EQ((batch_encoder.Decode<int64_t, 1>(plain)), 123 + 23);

  res = evaluator->Add(ct0, batch_encoder.Encode<int64_t>(-123, -456));
  decryptor->Decrypt(res, &plain);
  EXPECT_EQ((batch_encoder.Decode<int64_t, 0>(plain)), -123 - 123);
  EXPECT_EQ((batch_encoder.Decode<int64_t, 1>(plain)), 123 - 456);

  res = evaluator->Add(
      ct0, batch_encoder.Encode<int64_t>(std::numeric_limits<int64_t>::max(),
                                         std::numeric_limits<int64_t>::max()));
  decryptor->Decrypt(res, &plain);
  EXPECT_EQ((batch_encoder.Decode<int64_t, 0>(plain)),
            -123LL + std::numeric_limits<int64_t>::max());
  EXPECT_EQ((batch_encoder.Decode<int64_t, 1>(plain)),
            std::numeric_limits<int64_t>::lowest() + 122);  // overflow

  // test big number
  ct0 = encryptor->Encrypt(
      batch_encoder.Encode<int64_t>(std::numeric_limits<int64_t>::lowest(),
                                    std::numeric_limits<int64_t>::max()));
  res = evaluator->Add(
      ct0, batch_encoder.Encode<int64_t>(std::numeric_limits<int64_t>::max(),
                                         std::numeric_limits<int64_t>::max()));
  decryptor->Decrypt(res, &plain);
  EXPECT_EQ((batch_encoder.Decode<int64_t, 0>(plain)), -1);
  EXPECT_EQ((batch_encoder.Decode<int64_t, 1>(plain)), -2);

  res = evaluator->Add(ct0, batch_encoder.Encode<int64_t>(-1, 1));
  decryptor->Decrypt(res, &plain);
  EXPECT_EQ((batch_encoder.Decode<int64_t, 0>(plain)),
            std::numeric_limits<int64_t>::max());
  EXPECT_EQ((batch_encoder.Decode<int64_t, 1>(plain)),
            std::numeric_limits<int64_t>::lowest());
}

TEST_P(BatchEvalTest, BatchAdd) {
  if (GetParam() == SchemaType::ElGamal) {
    GTEST_SKIP() << "Plaintext range is not enough, Skip ElGamal";
  }
  if (GetParam() == SchemaType::DGK) {
    GTEST_SKIP() << "Plaintext range is not enough, Skip DGK";
  }

  auto encryptor = he_kit_.GetEncryptor();
  auto evaluator = he_kit_.GetEvaluator();
  auto decryptor = he_kit_.GetDecryptor();
  BatchEncoder batch_encoder(GetParam());

  auto sum = encryptor->EncryptZero();
  int64_t size = 1000;
  for (int64_t i = 0; i < size; ++i) {
    evaluator->AddInplace(&sum, batch_encoder.Encode<int64_t>(i, -i));
  }

  auto plain = decryptor->Decrypt(sum);
  EXPECT_EQ((batch_encoder.Decode<int64_t, 0>(plain)), (size - 1) * size / 2);
  EXPECT_EQ((batch_encoder.Decode<int64_t, 1>(plain)), -(size - 1) * size / 2);
}

}  // namespace heu::lib::phe::test
