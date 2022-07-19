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

#include "heu/library/algorithms/mock/mock.h"

#include <string>

#include "gtest/gtest.h"

namespace heu::lib::algorithms::mock::test {

class MockHeTest : public testing::Test {
 protected:
  void SetUp() override { KeyGenerator::Generate(2048, &sk_, &pk_); }

 protected:
  SecretKey sk_;
  PublicKey pk_;
};

TEST_F(MockHeTest, Serialize) {
  auto pk_buffer = pk_.Serialize();

  PublicKey pk2;
  pk2.Deserialize(yasl::ByteContainerView(pk_buffer));
  Encryptor encryptor(pk2);
  Evaluator evaluator(pk2);

  auto sk_buffer = sk_.Serialize();

  MPInt m0(-12345);
  Ciphertext ct = encryptor.Encrypt(m0);

  MPInt dc;
  Decryptor decryptor(pk_, sk_);
  decryptor.Decrypt(ct, &dc);
  EXPECT_EQ(dc, m0);

  Ciphertext ct2 = evaluator.Mul(ct, m0);

  SecretKey sk2;
  sk2.Deserialize(yasl::ByteContainerView(sk_buffer));
  Decryptor decryptor2(pk2, sk2);
  decryptor2.Decrypt(ct2, &dc);
  EXPECT_EQ(dc, m0 * m0);
}

TEST_F(MockHeTest, CiphertextEvaluate) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  MPInt m0(-12345);
  Ciphertext ct0 = encryptor.Encrypt(m0);

  Ciphertext res;
  MPInt plain;

  res = evaluator.Add(ct0, ct0);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-12345 * 2));
  res = evaluator.Mul(ct0, MPInt(2));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-12345 * 2));

  evaluator.Randomize(&res);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-12345 * 2));

  MPInt m1(123);
  Ciphertext ct1 = encryptor.Encrypt(m1);

  res = evaluator.Add(ct1, ct1);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123 * 2));
  res = evaluator.Mul(ct1, MPInt(2));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123 * 2));

  res = evaluator.Add(ct0, ct1);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-12345 + 123));

  // mul
  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, MPInt(1));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123));

  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, MPInt(0));
  decryptor.Decrypt(res, &plain);
  EXPECT_TRUE(plain.IsZero());
  decryptor.Decrypt(res, &plain);
  EXPECT_TRUE(plain.IsZero());

  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, MPInt(-1));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123));

  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, MPInt(-2));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123 * 2));
}

TEST_F(MockHeTest, PlaintextEvaluate1) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  // base (m0) 为正数
  MPInt m0(123);
  Ciphertext ct0 = encryptor.Encrypt(m0);

  Ciphertext res;
  MPInt plain;
  res = evaluator.Add(ct0, MPInt(23));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123 + 23));

  res = evaluator.Add(ct0, MPInt(6543212));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123 + 6543212));

  res = evaluator.Add(ct0, MPInt(-123));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(0));

  res = evaluator.Add(ct0, MPInt(-456));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(123 - 456));
}

TEST_F(MockHeTest, PlaintextEvaluate2) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  // base (m0) 为负数
  MPInt m0(-123);
  Ciphertext ct0 = encryptor.Encrypt(m0);

  MPInt plain;
  Ciphertext res = evaluator.Add(ct0, MPInt(23));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123 + 23));

  res = evaluator.Add(ct0, MPInt(std::numeric_limits<int64_t>::max()));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123 + std::numeric_limits<int64_t>::max()));

  res = evaluator.Add(ct0, MPInt(-123));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123 * 2));

  res = evaluator.Add(ct0, MPInt(-456));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-123 - 456));

  // test big number
  ct0 = encryptor.Encrypt(MPInt(std::numeric_limits<int64_t>::lowest()));
  res = evaluator.Add(ct0, MPInt(std::numeric_limits<int64_t>::max()));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, MPInt(-1));

  res = evaluator.Add(ct0, MPInt(-1));
  decryptor.Decrypt(res, &plain);
  // MPInt 本身不会溢出，AsInt64() 溢出
  EXPECT_EQ(plain.As<int64_t>(), std::numeric_limits<int64_t>::max());
}

TEST_F(MockHeTest, TestInvertMod) {
  MPInt a(667);
  MPInt::InvertMod(a, MPInt(561613), &a);
  EXPECT_EQ(842, a.As<double>());
}

class NegateInplaceTest : public ::testing::TestWithParam<int64_t> {
 protected:
  void SetUp() override { KeyGenerator::Generate(2048, &sk_, &pk_); }

 protected:
  SecretKey sk_;
  PublicKey pk_;
};

INSTANTIATE_TEST_SUITE_P(
    TestNegate, NegateInplaceTest,
    ::testing::Values(-123, 123, 0, 1, -1, 55555,
                      std::numeric_limits<int64_t>::max()));

TEST_P(NegateInplaceTest, TestNegate) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  Ciphertext ct0;
  MPInt plain;
  int in = GetParam();

  // 负数
  ct0 = encryptor.Encrypt(MPInt(in));
  evaluator.NegateInplace(&ct0);
  decryptor.Decrypt(ct0, &plain);
  EXPECT_EQ(plain, MPInt(-in));
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

  MPInt x_mp(x);
  MPInt r_mp(share_a);

  Ciphertext x_encrypted = encryptor.Encrypt(x_mp);

  evaluator.SubInplace(&x_encrypted, r_mp);
  MPInt raw;
  decryptor.Decrypt(x_encrypted, &raw);
  int64_t share_b = raw.As<int64_t>();

  EXPECT_EQ(share_a + share_b, x);
}

}  // namespace heu::lib::algorithms::mock::test
