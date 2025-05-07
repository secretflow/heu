// Copyright 2023 zhangwfjh
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

#include "heu/library/algorithms/dgk/dgk.h"

#include <string>

#include "gtest/gtest.h"

namespace heu::lib::algorithms::dgk::test {

class DGKTest : public ::testing::Test {
 protected:
  void SetUp() override {
    KeyGenerator::Generate(2048, &sk_, &pk_);
    evaluator_ = std::make_shared<Evaluator>(pk_);
    decryptor_ = std::make_shared<Decryptor>(pk_, sk_);
    encryptor_ = std::make_shared<Encryptor>(pk_);
  }

 protected:
  SecretKey sk_;
  PublicKey pk_;
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Evaluator> evaluator_;
  std::shared_ptr<Decryptor> decryptor_;
};

TEST_F(DGKTest, KeySerialization) {
  auto pk_serialization = pk_.Serialize();
  auto sk_serialization = sk_.Serialize();
  PublicKey pk;
  pk.Deserialize(pk_serialization);
  SecretKey sk;
  sk.Deserialize(sk_serialization);
  EXPECT_EQ(sk.Decrypt(pk.MapBackToZSpace(pk.Encrypt(BigInt{123}))), 123);
}

TEST_F(DGKTest, CiphertextEvaluate) {
  Plaintext m0(-12345);
  Ciphertext ct0 = encryptor_->Encrypt(m0);

  Ciphertext res;
  Plaintext plain;

  res = evaluator_->Add(ct0, ct0);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, -12345 * 2);
  res = evaluator_->Mul(ct0, Plaintext(2));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, -12345 * 2);

  evaluator_->Randomize(&res);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, -12345 * 2);

  Plaintext m1(123);
  Ciphertext ct1 = encryptor_->Encrypt(m1);

  res = evaluator_->Add(ct1, ct1);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, 123 * 2);
  res = evaluator_->Mul(ct1, Plaintext(2));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, 123 * 2);

  res = evaluator_->Add(ct0, ct1);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, -12345 + 123);

  // mul
  ct1 = encryptor_->Encrypt(m1);
  res = evaluator_->Mul(ct1, Plaintext(1));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, 123);

  ct1 = encryptor_->Encrypt(m1);
  res = evaluator_->Mul(ct1, Plaintext(0));
  decryptor_->Decrypt(res, &plain);
  EXPECT_TRUE(plain.IsZero());
  evaluator_->Randomize(&res);
  EXPECT_FALSE(res.c_.IsZero());
  decryptor_->Decrypt(res, &plain);
  EXPECT_TRUE(plain.IsZero());

  ct1 = encryptor_->Encrypt(m1);
  res = evaluator_->Mul(ct1, Plaintext(-1));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, -123);

  ct1 = encryptor_->Encrypt(m1);
  res = evaluator_->Mul(ct1, Plaintext(-2));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, -123 * 2);
}

TEST_F(DGKTest, MinMaxDecrypt) {
  Plaintext plain = pk_.PlainModule();
  EXPECT_THROW(encryptor_->Encrypt(plain), std::exception);  // too many bits

  plain = pk_.PlaintextBound() + 1;
  EXPECT_THROW(encryptor_->Encrypt(plain), std::exception);  // too many bits

  Plaintext plain2;
  --plain;  // max
  Ciphertext ct0 = encryptor_->Encrypt(plain);
  decryptor_->Decrypt(ct0, &plain2);
  EXPECT_EQ(plain, plain2);

  plain.NegateInplace();  // -max
  ct0 = encryptor_->Encrypt(plain);
  decryptor_->Decrypt(ct0, &plain2);
  EXPECT_EQ(plain, plain2);

  --plain;
  EXPECT_THROW(encryptor_->Encrypt(plain),
               std::exception);  // too many bits
}

TEST_F(DGKTest, PlaintextEvaluate) {
  // base (m0) 为正数
  Plaintext m0(123);
  Ciphertext ct0 = encryptor_->Encrypt(m0);

  Ciphertext res;
  Plaintext plain;
  res = evaluator_->Add(ct0, Plaintext(23));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, 123 + 23);

  res = evaluator_->Add(ct0, Plaintext(654));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, 123 + 654);

  res = evaluator_->Add(ct0, Plaintext(-123));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, 0);

  res = evaluator_->Add(ct0, Plaintext(-456));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, 123 - 456);
}

}  // namespace heu::lib::algorithms::dgk::test
