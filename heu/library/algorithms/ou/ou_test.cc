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

#include "heu/library/algorithms/ou/ou.h"

#include <string>

#include "gtest/gtest.h"

namespace heu::lib::algorithms::ou::test {

class OUTest : public testing::Test {
 protected:
  static void SetUpTestSuite() { KeyGenerator::Generate(2048, &sk_, &pk_); }

  static SecretKey sk_;
  static PublicKey pk_;
};

SecretKey OUTest::sk_;
PublicKey OUTest::pk_;

TEST_F(OUTest, Serialize) {
  auto pk_buffer = pk_.Serialize();

  PublicKey pk2;
  pk2.Deserialize(pk_buffer);
  ASSERT_EQ(pk_.n_, pk2.n_);
  ASSERT_EQ(pk_.capital_g_, pk2.capital_g_);
  ASSERT_EQ(pk_.capital_h_, pk2.capital_h_);
  ASSERT_EQ(pk_.capital_g_inv_, pk2.capital_g_inv_);
  ASSERT_EQ(pk_.PlaintextBound(), pk2.PlaintextBound());

  Encryptor encryptor(pk2);
  Evaluator evaluator(pk2);

  auto sk_buffer = sk_.Serialize();

  BigInt m0(-12345);
  Ciphertext ct = encryptor.Encrypt(m0);

  BigInt dc;
  Decryptor decryptor(pk_, sk_);
  decryptor.Decrypt(ct, &dc);
  EXPECT_EQ(dc, m0);

  Ciphertext ct2 = evaluator.Mul(ct, m0);

  SecretKey sk2;
  sk2.Deserialize((sk_buffer));
  Decryptor decryptor2(pk2, sk2);
  decryptor2.Decrypt(ct2, &dc);
  EXPECT_EQ(dc, m0 * m0);
}

TEST_F(OUTest, CiphertextEvaluate) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  BigInt m0(-12345);
  Ciphertext ct0 = encryptor.Encrypt(m0);

  Ciphertext res;
  BigInt plain;

  res = evaluator.Add(ct0, ct0);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -12345 * 2);
  res = evaluator.Mul(ct0, BigInt(2));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -12345 * 2);

  evaluator.Randomize(&res);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -12345 * 2);

  BigInt m1(123);
  Ciphertext ct1 = encryptor.Encrypt(m1);

  res = evaluator.Add(ct1, ct1);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, 123 * 2);
  res = evaluator.Mul(ct1, BigInt(2));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, 123 * 2);

  res = evaluator.Add(ct0, ct1);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -12345 + 123);

  // mul
  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, BigInt(1));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, 123);

  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, BigInt(0));
  decryptor.Decrypt(res, &plain);
  EXPECT_TRUE(plain.IsZero());
  evaluator.Randomize(&res);
  EXPECT_FALSE(res.c_.IsZero());
  decryptor.Decrypt(res, &plain);
  EXPECT_TRUE(plain.IsZero());

  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, BigInt(-1));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -123);

  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, BigInt(-2));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -123 * 2);
}

TEST_F(OUTest, MinMaxDecrypt) {
  Encryptor encryptor(pk_);
  Decryptor decryptor(pk_, sk_);

  BigInt plain = sk_.p_ / 2;
  EXPECT_THROW(encryptor.Encrypt(plain), std::exception);  // too many bits

  plain = pk_.PlaintextBound() + 1;
  EXPECT_THROW(encryptor.Encrypt(plain), std::exception);  // too many bits

  BigInt plain2;
  --plain;  // max
  Ciphertext ct0 = encryptor.Encrypt(plain);
  decryptor.Decrypt(ct0, &plain2);
  EXPECT_EQ(plain, plain2);

  plain.NegateInplace();  // -max
  ct0 = encryptor.Encrypt(plain);
  decryptor.Decrypt(ct0, &plain2);
  EXPECT_EQ(plain, plain2);

  --plain;  // too many bits
  EXPECT_THROW(encryptor.Encrypt(plain), std::exception);
}

TEST_F(OUTest, PlaintextEvaluate1) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  // base (m0) 为正数
  BigInt m0(123);
  Ciphertext ct0 = encryptor.Encrypt(m0);

  Ciphertext res;
  BigInt plain;
  res = evaluator.Add(ct0, BigInt(23));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, 123 + 23);

  res = evaluator.Add(ct0, BigInt(6543212));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, 123 + 6543212);

  res = evaluator.Add(ct0, BigInt(-123));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, 0);

  res = evaluator.Add(ct0, BigInt(-456));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, 123 - 456);
}

TEST_F(OUTest, PlaintextEvaluate2) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  // base (m0) 为负数
  BigInt m0(-123);
  Ciphertext ct0 = encryptor.Encrypt(m0);

  BigInt plain;
  Ciphertext res = evaluator.Add(ct0, BigInt(23));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -123 + 23);

  res = evaluator.Add(ct0, BigInt(std::numeric_limits<int64_t>::max()));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -123 + std::numeric_limits<int64_t>::max());

  res = evaluator.Add(ct0, BigInt(-123));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -123 * 2);

  res = evaluator.Add(ct0, BigInt(-456));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -123 - 456);

  // test big number
  ct0 = encryptor.Encrypt(BigInt(std::numeric_limits<int64_t>::lowest()));
  res = evaluator.Add(ct0, BigInt(std::numeric_limits<int64_t>::max()));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, -1);

  res = evaluator.Add(ct0, BigInt(-1));
  decryptor.Decrypt(res, &plain);
  // BigInt 本身不会溢出，AsInt64() 溢出
  EXPECT_EQ(plain.Get<int64_t>(), std::numeric_limits<int64_t>::max());
}

TEST_F(OUTest, TestInvertMod) {
  BigInt a(667);
  a = a.InvMod(BigInt(561613));
  EXPECT_EQ(a, 842);
}

class BigNumberTest : public ::testing::TestWithParam<int64_t> {
 protected:
  void SetUp() override { KeyGenerator::Generate(2048, &sk_, &pk_); }

 protected:
  SecretKey sk_;
  PublicKey pk_;
};

// int64 range: [-9223372036854775808, 9223372036854775807]
INSTANTIATE_TEST_SUITE_P(
    SubTest, BigNumberTest,
    ::testing::Values(std::numeric_limits<int64_t>::lowest(), -1234, -1, 0, 1,
                      1234, std::numeric_limits<int64_t>::max()));

TEST_P(BigNumberTest, SubTest) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  int64_t x = GetParam();
  int64_t share_a = std::numeric_limits<int64_t>::max();

  BigInt x_mp(x);
  BigInt r_mp(share_a);

  Ciphertext x_encrypted = encryptor.Encrypt(x_mp);

  evaluator.SubInplace(&x_encrypted, r_mp);
  BigInt raw;
  decryptor.Decrypt(x_encrypted, &raw);
  int64_t share_b = raw.Get<int64_t>();

  EXPECT_EQ(share_a + share_b, x);
}

}  // namespace heu::lib::algorithms::ou::test
