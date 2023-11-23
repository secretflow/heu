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

#include "heu/library/algorithms/paillier_ic/paillier.h"

#include <string>

#include "gtest/gtest.h"

namespace heu::lib::algorithms::paillier_ic::test {

class IcPaillierTest : public ::testing::Test {
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

TEST_F(IcPaillierTest, CiphertextEvaluate) {
  EXPECT_GT(encryptor_->GetRn(), MPInt(1));

  MPInt m0(-12345);
  Ciphertext ct0 = encryptor_->Encrypt(m0);

  Ciphertext res;
  MPInt plain;

  res = evaluator_->Add(ct0, ct0);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-12345 * 2));
  res = evaluator_->Mul(ct0, MPInt(2));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-12345 * 2));

  evaluator_->Randomize(&res);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-12345 * 2));

  MPInt m1(123);
  Ciphertext ct1 = encryptor_->Encrypt(m1);

  res = evaluator_->Add(ct1, ct1);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123 * 2));
  res = evaluator_->Mul(ct1, MPInt(2));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123 * 2));

  res = evaluator_->Add(ct0, ct1);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-12345 + 123));

  // mul
  ct1 = encryptor_->Encrypt(m1);
  res = evaluator_->Mul(ct1, MPInt(1));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123));

  ct1 = encryptor_->Encrypt(m1);
  res = evaluator_->Mul(ct1, MPInt(0));
  decryptor_->Decrypt(res, &plain);
  EXPECT_TRUE(plain.IsZero());
  evaluator_->Randomize(&res);
  EXPECT_FALSE(res.c_.IsZero());
  decryptor_->Decrypt(res, &plain);
  EXPECT_TRUE(plain.IsZero());

  ct1 = encryptor_->Encrypt(m1);
  res = evaluator_->Mul(ct1, MPInt(-1));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123));

  ct1 = encryptor_->Encrypt(m1);
  res = evaluator_->Mul(ct1, MPInt(-2));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123 * 2));
}

TEST_F(IcPaillierTest, MinMaxDecrypt) {
  MPInt plain = pk_.n_;
  EXPECT_THROW(encryptor_->Encrypt(plain), std::exception);  // too many bits

  plain = pk_.PlaintextBound() + 1_mp;
  EXPECT_THROW(encryptor_->Encrypt(plain), std::exception);  // too many bits

  MPInt plain2;
  plain.DecrOne();  // max
  Ciphertext ct0 = encryptor_->Encrypt(plain);
  decryptor_->Decrypt(ct0, &plain2);
  EXPECT_EQ(plain, plain2);

  plain.NegateInplace();  // -max
  ct0 = encryptor_->Encrypt(plain);
  decryptor_->Decrypt(ct0, &plain2);
  EXPECT_EQ(plain, plain2);

  plain.DecrOne();  // too many bits
  EXPECT_THROW(encryptor_->Encrypt(plain), std::exception);
}

TEST_F(IcPaillierTest, PlaintextEvaluate1) {
  // base (m0) 为正数
  MPInt m0(123);
  Ciphertext ct0 = encryptor_->Encrypt(m0);

  Ciphertext res;
  MPInt plain;
  res = evaluator_->Add(ct0, MPInt(23));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123 + 23));

  res = evaluator_->Add(ct0, MPInt(6543212));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123 + 6543212));

  res = evaluator_->Add(ct0, MPInt(-123));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(0));

  res = evaluator_->Add(ct0, MPInt(-456));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123 - 456));
}

TEST_F(IcPaillierTest, PlaintextEvaluate2) {
  // test case: base (m0) is negative
  MPInt m0(-123);
  Ciphertext ct0 = encryptor_->Encrypt(m0);

  MPInt plain;
  Ciphertext res = evaluator_->Add(ct0, MPInt(23));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123 + 23));

  res = evaluator_->Add(ct0, MPInt(std::numeric_limits<int64_t>::max()));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123 + std::numeric_limits<int64_t>::max()));

  res = evaluator_->Add(ct0, MPInt(-123));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123 * 2));

  res = evaluator_->Add(ct0, MPInt(-456));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123 - 456));

  // test big number
  ct0 = encryptor_->Encrypt(MPInt(std::numeric_limits<int64_t>::lowest()));
  res = evaluator_->Add(ct0, MPInt(std::numeric_limits<int64_t>::max()));
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-1));

  res = evaluator_->Add(ct0, MPInt(-1));
  decryptor_->Decrypt(res, &plain);
  // note: MPInt itself does not overflow, but AsInt64() overflows
  EXPECT_EQ(plain.Get<int64_t>(), std::numeric_limits<int64_t>::max());
}

}  // namespace heu::lib::algorithms::paillier_ic::test
