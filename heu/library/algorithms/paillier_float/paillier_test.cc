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

#include "heu/library/algorithms/paillier_float/paillier.h"

#include "gtest/gtest.h"

namespace heu::lib::algorithms::paillier_f::test {

class PaillierTest : public testing::Test {
 protected:
  void SetUp() override {
    // key_size = 1024, to speed up unittest
    KeyGenerator::Generate(2048, &sec_key_, &pub_key_);
  }

 protected:
  PublicKey pub_key_;
  SecretKey sec_key_;
};

TEST_F(PaillierTest, EncryptMPIntWorks) {
  MPInt p_10(10);

  // 1. encrypt
  Encryptor encryptor(pub_key_);
  Ciphertext c1 = encryptor.Encrypt(p_10);
  Ciphertext c2 = encryptor.Encrypt(p_10);

  EXPECT_FALSE(c1 == c2);

  auto ca = encryptor.EncryptWithAudit(p_10);

  EXPECT_FALSE(c1 == ca.first);

  // 2. decrypt
  Decryptor decryptor(pub_key_, sec_key_);
  MPInt p1(0), p2(0), pa(0);

  decryptor.Decrypt(c1, &p1);
  decryptor.Decrypt(c2, &p2);
  decryptor.Decrypt(ca.first, &pa);

  // 3. compare
  EXPECT_EQ(p1, p_10);
  EXPECT_EQ(p2, p_10);
  EXPECT_EQ(pa, p_10);
}

TEST_F(PaillierTest, EncryptDoubleWorks) {
  double pi(3.1415);

  // 1. encrypt
  Encryptor encryptor(pub_key_);
  Ciphertext c1 = encryptor.Encrypt(pi);
  Ciphertext c2 = encryptor.Encrypt(pi);

  EXPECT_FALSE(c1 == c2);

  // 2. decrypt
  Decryptor decryptor(pub_key_, sec_key_);
  double p1, p2;

  decryptor.Decrypt(c1, &p1);
  decryptor.Decrypt(c2, &p2);

  EXPECT_DOUBLE_EQ(p1, pi);
  EXPECT_DOUBLE_EQ(p2, pi);
}

TEST_F(PaillierTest, EncryptedAddWorks) {
  MPInt p1(59);
  MPInt p2(3540);
  MPInt p3 = p1 + p2;

  // encrypt p1 -> c1, p2 -> c2
  Encryptor encryptor(pub_key_);
  Ciphertext c1 = encryptor.Encrypt(p1);
  Ciphertext c2 = encryptor.Encrypt(p2);

  // c1 += c2
  Evaluator evaluator(pub_key_);
  evaluator.AddInplace(&c1, c2);

  // decrypt
  Decryptor decryptor(pub_key_, sec_key_);
  MPInt sum(0);
  decryptor.Decrypt(c1, &sum);

  EXPECT_EQ(sum, p3);
}

TEST_F(PaillierTest, CipherAddPlainMPIntWorks) {
  MPInt p1(59);
  MPInt p2(3540);
  MPInt p3 = p1 + p2;

  Encryptor encryptor(pub_key_);
  Ciphertext c1 = encryptor.Encrypt(p1);

  Evaluator evaluator(pub_key_);
  evaluator.AddInplace(&c1, p2);

  Decryptor decryptor(pub_key_, sec_key_);
  MPInt sum(0);
  decryptor.Decrypt(c1, &sum);

  EXPECT_EQ(sum, p3);
}

TEST_F(PaillierTest, CipherMultiplyPlainMPIntWorks) {
  MPInt p1(59);
  MPInt p2(3540);
  MPInt p3 = p1 * p2;

  Encryptor encryptor(pub_key_);
  Ciphertext c1 = encryptor.Encrypt(p1);

  Evaluator evaluator(pub_key_);
  evaluator.MulInplace(&c1, p2);

  Decryptor decryptor(pub_key_, sec_key_);
  MPInt product(0);
  decryptor.Decrypt(c1, &product);

  EXPECT_EQ(product, p3);
}

TEST_F(PaillierTest, CipherMultiplyDoubleWorks) {
  MPInt p1(125);
  double p2 = 0.1;

  Encryptor encryptor(pub_key_);
  Ciphertext c1 = encryptor.Encrypt(p1);

  Evaluator evaluator(pub_key_);
  evaluator.MulInplace(&c1, p2);

  Decryptor decryptor(pub_key_, sec_key_);
  MPInt product;
  decryptor.Decrypt(c1, &product);

  EXPECT_EQ(product.Get<int64_t>(),
            static_cast<int64_t>(p1.Get<double>() * p2));
}

class NegateInplaceTest : public ::testing::TestWithParam<int> {
 protected:
  void SetUp() override { KeyGenerator::Generate(2048, &sk_, &pk_); }

 protected:
  SecretKey sk_;
  PublicKey pk_;
};

INSTANTIATE_TEST_SUITE_P(TestNegate, NegateInplaceTest,
                         ::testing::Values(-123, 123, 0, 1, -1, 55555,
                                           0xFFFFFFFFFFFFFFF1));

TEST_P(NegateInplaceTest, TestNegate) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  int in = GetParam();

  Ciphertext ct0 = encryptor.Encrypt(MPInt(in));
  evaluator.NegateInplace(&ct0);

  MPInt plain;
  decryptor.Decrypt(ct0, &plain);
  EXPECT_EQ(plain, MPInt(-in));
}

}  // namespace heu::lib::algorithms::paillier_f::test
