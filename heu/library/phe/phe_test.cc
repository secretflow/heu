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

#include "heu/library/phe/phe.h"

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "heu/library/phe/encoding/encoding.h"

namespace heu::lib::phe::test {

class PheTest : public ::testing::TestWithParam<SchemaType> {
 protected:
  void SetUp() override {
    auto sk_str = he_kit_.GetSecretKey()->ToString();
    EXPECT_GT(sk_str.length(), 30) << sk_str;
    auto pk_str = he_kit_.GetPublicKey()->ToString();
    EXPECT_GT(pk_str.length(), 30) << pk_str;
  }

 protected:
  HeKit he_kit_ = HeKit(GetParam());
  PlainEncoder edr = he_kit_.GetEncoder<PlainEncoder>(1);
};

INSTANTIATE_TEST_SUITE_P(Schema, PheTest, ::testing::ValuesIn(GetAllSchema()));

TEST_P(PheTest, KeySerialize) {
  // test pk
  auto buffer_pk = he_kit_.GetPublicKey()->Serialize();
  EXPECT_NE(*he_kit_.GetPublicKey(), PublicKey());
  EXPECT_NE(*he_kit_.GetPublicKey(), PublicKey(he_kit_.GetSchemaType()));
  PublicKey pk;
  pk.Deserialize(buffer_pk);
  EXPECT_EQ(*he_kit_.GetPublicKey(), pk);

  // test sk
  auto buffer_sk = he_kit_.GetSecretKey()->Serialize();
  EXPECT_NE(*he_kit_.GetSecretKey(), SecretKey());
  EXPECT_NE(*he_kit_.GetSecretKey(), SecretKey(he_kit_.GetSchemaType()));
  SecretKey sk;
  sk.Deserialize(buffer_sk);
  EXPECT_EQ(*he_kit_.GetSecretKey(), sk);
}

TEST_P(PheTest, VarSerialize) {
  // test serialize plaintext
  auto clear = he_kit_.GetSchemaType() == SchemaType::DGK ? -9632 : -963258741;
  auto plain = Plaintext(he_kit_.GetSchemaType(), clear);
  EXPECT_NE(plain, Plaintext());
  EXPECT_NE(plain, Plaintext(he_kit_.GetSchemaType()));
  EXPECT_NE(plain, Plaintext(he_kit_.GetSchemaType(), -clear));
  EXPECT_EQ(plain, Plaintext(he_kit_.GetSchemaType(), clear));
  auto buffer = plain.Serialize();
  Plaintext pt2;
  pt2.Deserialize(buffer);
  EXPECT_EQ(plain, pt2);

  // test serialize ciphertext
  auto ct0 = he_kit_.GetEncryptor()->Encrypt(plain);
  EXPECT_GE(ct0.ToString().length(), 10) << ct0.ToString();
  EXPECT_NE(ct0, Ciphertext());
  EXPECT_NE(ct0, Ciphertext(he_kit_.GetSchemaType()));
  buffer = ct0.Serialize();
  EXPECT_GT(buffer.size(), sizeof(size_t)) << buffer;

  Ciphertext ct1;
  ct1.Deserialize(buffer);
  EXPECT_EQ(ct0, ct1);
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(ct1), plain);

  // test serialize public key
  auto buffer_pk = he_kit_.GetPublicKey()->Serialize();
  DestinationHeKit server(buffer_pk);
  server.GetEvaluator()->AddInplace(&ct1, edr.Encode(666));
  server.GetEvaluator()->Randomize(&ct1);
  buffer = ct1.Serialize();

  // send back to client
  Ciphertext ct2;
  ct2.Deserialize(buffer);
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(ct1), plain + edr.Encode(666));
}

// test batch encoding
TEST_P(PheTest, BatchEncoding) {
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

TEST_P(PheTest, BatchAdd) {
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
