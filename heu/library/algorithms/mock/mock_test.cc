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

  Plaintext m0;
  m0.Set(-12345);
  Ciphertext ct = encryptor.Encrypt(m0);

  Plaintext dc;
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

  Plaintext m0;
  m0.Set(-12345);
  Ciphertext ct0 = encryptor.Encrypt(m0);

  Ciphertext res;
  Plaintext plain;

  res = evaluator.Add(ct0, ct0);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain.Get<int64_t>(), -12345 * 2);
  res = evaluator.Mul(ct0, Plaintext(2));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain.Get<int64_t>(), (-12345 * 2));

  evaluator.Randomize(&res);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain.Get<int64_t>(), (-12345 * 2));

  Plaintext m1(123);
  Ciphertext ct1 = encryptor.Encrypt(m1);

  res = evaluator.Add(ct1, ct1);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain.Get<int64_t>(), (123 * 2));
  res = evaluator.Mul(ct1, Plaintext(2));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain.Get<int64_t>(), (123 * 2));

  res = evaluator.Add(ct0, ct1);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain.Get<int64_t>(), (-12345 + 123));

  // mul
  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, Plaintext(1));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain.Get<int64_t>(), (123));

  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, Plaintext(0));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain.Get<int64_t>(), 0);
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain.Get<int64_t>(), 0);

  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, Plaintext(-1));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-123));

  ct1 = encryptor.Encrypt(m1);
  res = evaluator.Mul(ct1, Plaintext(-2));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-123 * 2));
}

TEST_F(MockHeTest, PlaintextEvaluate1) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  // base (m0) 为正数
  Plaintext m0(123);
  Ciphertext ct0 = encryptor.Encrypt(m0);

  Ciphertext res;
  Plaintext plain;
  res = evaluator.Add(ct0, Plaintext(23));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(123 + 23));

  res = evaluator.Add(ct0, Plaintext(6543212));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(123 + 6543212));

  res = evaluator.Add(ct0, Plaintext(-123));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(0));

  res = evaluator.Add(ct0, Plaintext(-456));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(123 - 456));
}

TEST_F(MockHeTest, PlaintextEvaluate2) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  // base (m0) 为负数
  Plaintext m0(-123);
  Ciphertext ct0 = encryptor.Encrypt(m0);

  Plaintext plain;
  Ciphertext res = evaluator.Add(ct0, Plaintext(23));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-123 + 23));

  res = evaluator.Add(ct0, Plaintext(std::numeric_limits<int64_t>::max()));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-123 + std::numeric_limits<int64_t>::max()));

  res = evaluator.Add(ct0, Plaintext(-123));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-123 * 2));

  res = evaluator.Add(ct0, Plaintext(-456));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-123 - 456));

  // test big number
  ct0 = encryptor.Encrypt(Plaintext(std::numeric_limits<int64_t>::lowest()));
  res = evaluator.Add(ct0, Plaintext(std::numeric_limits<int64_t>::max()));
  decryptor.Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-1));

  res = evaluator.Add(ct0, Plaintext(-1));
  decryptor.Decrypt(res, &plain);
  // Plaintext 本身不会溢出，AsInt64() 溢出
  EXPECT_EQ(plain.Get<int64_t>(), std::numeric_limits<int64_t>::max());
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
  Plaintext plain;
  int in = GetParam();

  // 负数
  ct0 = encryptor.Encrypt(Plaintext(in));
  evaluator.NegateInplace(&ct0);
  decryptor.Decrypt(ct0, &plain);
  EXPECT_EQ(plain, Plaintext(-in));
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

  Plaintext x_mp(x);
  Plaintext r_mp(share_a);

  Ciphertext x_encrypted = encryptor.Encrypt(x_mp);

  evaluator.SubInplace(&x_encrypted, r_mp);
  Plaintext raw;
  decryptor.Decrypt(x_encrypted, &raw);
  int64_t share_b = raw.Get<int64_t>();

  EXPECT_EQ(share_a + share_b, x);
}

}  // namespace heu::lib::algorithms::mock::test
