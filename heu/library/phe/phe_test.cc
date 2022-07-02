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

#include "gtest/gtest.h"

#include "heu/library/phe/encoding/encoding.h"

namespace heu::lib::phe::test {

using algorithms::MPInt;

class PheTest : public ::testing::TestWithParam<SchemaType> {
 protected:
  void SetUp() override {
    he_kit_.Setup(GetParam(), 1024);
    auto sk_str = he_kit_.GetSecretKey()->ToString();
    EXPECT_GT(sk_str.length(), 10) << sk_str;
    auto pk_str = he_kit_.GetPublicKey()->ToString();
    EXPECT_GT(pk_str.length(), 10) << pk_str;
  }

 protected:
  HeKit he_kit_;
};

INSTANTIATE_TEST_SUITE_P(EachSchema, PheTest,
                         ::testing::Values(SchemaType::None,
                                           SchemaType::ZPaillier,
                                           SchemaType::FPaillier));

TEST_P(PheTest, Serialize) {
  MPInt plain(-963258741);
  auto ct0 = he_kit_.GetEncryptor()->Encrypt(plain);
  EXPECT_GE(ct0.ToString().length(), 10) << ct0.ToString();
  auto buffer = ct0.Serialize();
  EXPECT_GT(buffer.size(), sizeof(size_t)) << buffer;

  // test serialize ciphertext
  Ciphertext ct1;
  ct1.Deserialize(yasl::ByteContainerView(buffer));
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(ct1), plain);

  // test serialize public key
  auto buffer_pk = he_kit_.GetPublicKey()->Serialize();
  DestinationHeKit server;
  server.Setup(yasl::ByteContainerView(buffer_pk));
  server.GetEvaluator()->AddInplace(&ct1, MPInt(666));
  server.GetEvaluator()->Randomize(&ct1);
  buffer = ct1.Serialize();

  // send back to client
  Ciphertext ct2;
  ct2.Deserialize(yasl::ByteContainerView(buffer));
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(ct1), plain + 666);
}

TEST_P(PheTest, EncryptZero) {
  auto ct0 = he_kit_.GetEncryptor()->EncryptZero();
  MPInt plain;
  he_kit_.GetDecryptor()->Decrypt(ct0, &plain);
  ASSERT_EQ(plain, MPInt(0));

  he_kit_.GetEvaluator()->AddInplace(&ct0,
                                     he_kit_.GetEncryptor()->EncryptZero());
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0), MPInt(0));

  he_kit_.GetEvaluator()->SubInplace(&ct0,
                                     he_kit_.GetEncryptor()->EncryptZero());
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0), MPInt(0));

  auto p = he_kit_.GetEvaluator()->Sub(MPInt(123), ct0);
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(p), MPInt(123));

  he_kit_.GetEvaluator()->MulInplace(&ct0, MPInt(0));
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0), MPInt(0));

  he_kit_.GetEvaluator()->MulInplace(&ct0, MPInt(123456));
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0), MPInt(0));

  he_kit_.GetEvaluator()->NegateInplace(&ct0);
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0), MPInt(0));
}

TEST_P(PheTest, MinMaxEnc) {
  auto encryptor = he_kit_.GetEncryptor();
  auto decryptor = he_kit_.GetDecryptor();

  MPInt plain = he_kit_.GetPublicKey()->PlaintextBound();
  EXPECT_THROW(encryptor->Encrypt(plain), std::exception);  // too big

  plain.NegInplace();
  EXPECT_THROW(encryptor->Encrypt(plain), std::exception);  // too small

  MPInt plain2;
  plain = he_kit_.GetPublicKey()->PlaintextBound();
  plain.DecrOne();  // max
  Ciphertext ct0 = encryptor->Encrypt(plain);
  decryptor->Decrypt(ct0, &plain2);
  EXPECT_EQ(plain, plain2);

  plain.NegInplace();  // -max
  ct0 = encryptor->Encrypt(plain);
  decryptor->Decrypt(ct0, &plain2);
  EXPECT_EQ(plain, plain2);

  plain.DecrOne();
  EXPECT_THROW(encryptor->Encrypt(plain), std::exception);  // too small
}

TEST_P(PheTest, Evaluate) {
  auto encryptor = he_kit_.GetEncryptor();
  auto evaluator = he_kit_.GetEvaluator();
  auto decryptor = he_kit_.GetDecryptor();

  auto ct0 = encryptor->Encrypt(MPInt(-12345));
  evaluator->Randomize(&ct0);
  EXPECT_EQ(decryptor->Decrypt(ct0), MPInt(-12345));

  auto ct1 = evaluator->Negate(ct0);
  EXPECT_EQ(decryptor->Decrypt(ct1), MPInt(12345));

  // ADD //
  ct1 = evaluator->Add(ct0, ct0);
  EXPECT_EQ(decryptor->Decrypt(ct1), MPInt(-12345 * 2));

  ct1 = evaluator->Add(ct0, MPInt(345));
  EXPECT_EQ(decryptor->Decrypt(ct1), MPInt(-12345 + 345));

  // ADD - int64
  auto encoder = PlainEncoder(std::numeric_limits<int64_t>::max());
  auto imax = std::numeric_limits<int64_t>::max();
  auto ct_max = encryptor->Encrypt(encoder.Encode(imax - 1));
  ct1 = evaluator->Add(ct_max, encoder.Encode(1));
  EXPECT_EQ(encoder.Decode<int64_t>(decryptor->Decrypt(ct1)), imax);

  // SUB //
  ct1 = evaluator->Sub(ct0, ct0);
  EXPECT_EQ(decryptor->Decrypt(ct1), MPInt(0));

  ct1 = evaluator->Sub(ct0, MPInt(345));
  EXPECT_EQ(decryptor->Decrypt(ct1), MPInt(-12345 - 345));

  ct1 = evaluator->Sub(MPInt(789), ct0);
  EXPECT_EQ(decryptor->Decrypt(ct1), MPInt(12345 + 789));

  // SUB - int64
  auto umax = std::numeric_limits<uint64_t>::max();
  auto ct_umax = encryptor->Encrypt(encoder.Encode(umax));
  ct1 = evaluator->Sub(ct_umax, encoder.Encode(1));
  EXPECT_EQ(encoder.Decode<uint64_t>(decryptor->Decrypt(ct1)), umax - 1);

  // MUL //
  ct1 = evaluator->Mul(ct0, MPInt(0));
  EXPECT_EQ(decryptor->Decrypt(ct1), MPInt(-12345 * 0));

  ct1 = evaluator->Mul(ct0, MPInt(1));
  EXPECT_EQ(decryptor->Decrypt(ct1), MPInt(-12345 * 1));

  ct1 = evaluator->Mul(ct0, MPInt(2));
  EXPECT_EQ(decryptor->Decrypt(ct1), MPInt(-12345 * 2));

  ct1 = evaluator->Mul(ct0, MPInt(10));
  EXPECT_EQ(decryptor->Decrypt(ct1), MPInt(-12345 * 10));
}

TEST_P(PheTest, EvaluateInplace) {
  auto encryptor = he_kit_.GetEncryptor();
  auto evaluator = he_kit_.GetEvaluator();
  auto decryptor = he_kit_.GetDecryptor();

  MPInt pt0(9876);
  MPInt pt1(1234);
  auto ct0 = encryptor->Encrypt(pt0);
  auto ct1 = encryptor->Encrypt(pt1);
  evaluator->Randomize(&ct0);
  EXPECT_EQ(decryptor->Decrypt(ct0), MPInt(9876));

  evaluator->NegateInplace(&ct1);
  pt1.NegInplace();
  EXPECT_EQ(decryptor->Decrypt(ct1), pt1);

  // ADD //
  evaluator->AddInplace(&ct0, ct1);
  pt0 += pt1;
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);

  evaluator->AddInplace(&ct0, MPInt(963));
  pt0 += MPInt(963);
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);

  evaluator->AddInplace(&ct0, MPInt(-741));
  pt0 += MPInt(-741);
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);

  // SUB //
  evaluator->SubInplace(&ct0, ct1);
  pt0 -= pt1;
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);

  evaluator->SubInplace(&ct0, MPInt(852));
  pt0 -= MPInt(852);
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);

  // MUL //
  evaluator->MulInplace(&ct0, MPInt(10));
  pt0 *= MPInt(10);
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);
}

// test batch encoding
TEST_P(PheTest, BatchEncoding) {
  auto encryptor = he_kit_.GetEncryptor();
  auto evaluator = he_kit_.GetEvaluator();
  auto decryptor = he_kit_.GetDecryptor();
  BatchEncoder batch_encoder;

  MPInt m0 = batch_encoder.Encode<int64_t>(-123, 123);
  Ciphertext ct0 = encryptor->Encrypt(m0);

  MPInt plain;
  Ciphertext res = evaluator->Add(ct0, batch_encoder.Encode<int64_t>(23, 23));
  decryptor->Decrypt(res, &plain);
  EXPECT_EQ((batch_encoder.Get<int64_t, 0>(plain)), -123 + 23);
  EXPECT_EQ((batch_encoder.Get<int64_t, 1>(plain)), 123 + 23);

  res = evaluator->Add(ct0, batch_encoder.Encode<int64_t>(-123, -456));
  decryptor->Decrypt(res, &plain);
  EXPECT_EQ((batch_encoder.Get<int64_t, 0>(plain)), -123 - 123);
  EXPECT_EQ((batch_encoder.Get<int64_t, 1>(plain)), 123 - 456);

  res = evaluator->Add(
      ct0, batch_encoder.Encode<int64_t>(std::numeric_limits<int64_t>::max(),
                                         std::numeric_limits<int64_t>::max()));
  decryptor->Decrypt(res, &plain);
  EXPECT_EQ((batch_encoder.Get<int64_t, 0>(plain)),
            -123LL + std::numeric_limits<int64_t>::max());
  EXPECT_EQ((batch_encoder.Get<int64_t, 1>(plain)),
            std::numeric_limits<int64_t>::lowest() + 122);  // overflow

  // test big number
  ct0 = encryptor->Encrypt(
      batch_encoder.Encode<int64_t>(std::numeric_limits<int64_t>::lowest(),
                                    std::numeric_limits<int64_t>::max()));
  res = evaluator->Add(
      ct0, batch_encoder.Encode<int64_t>(std::numeric_limits<int64_t>::max(),
                                         std::numeric_limits<int64_t>::max()));
  decryptor->Decrypt(res, &plain);
  EXPECT_EQ((batch_encoder.Get<int64_t, 0>(plain)), -1);
  EXPECT_EQ((batch_encoder.Get<int64_t, 1>(plain)), -2);

  res = evaluator->Add(ct0, batch_encoder.Encode<int64_t>(-1, 1));
  decryptor->Decrypt(res, &plain);
  EXPECT_EQ((batch_encoder.Get<int64_t, 0>(plain)),
            std::numeric_limits<int64_t>::max());
  EXPECT_EQ((batch_encoder.Get<int64_t, 1>(plain)),
            std::numeric_limits<int64_t>::lowest());
}

}  // namespace heu::lib::phe::test
