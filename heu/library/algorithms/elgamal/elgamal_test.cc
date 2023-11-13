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

#include "heu/library/algorithms/elgamal/elgamal.h"

#include "gtest/gtest.h"
#include "yacl/utils/parallel.h"

namespace heu::lib::algorithms::elgamal::test {

class ElGamalTest : public testing::Test {
 protected:
  static void SetUpTestSuite() { KeyGenerator::Generate("sm2", &sk_, &pk_); }

  static SecretKey sk_;
  static PublicKey pk_;
};

SecretKey ElGamalTest::sk_;
PublicKey ElGamalTest::pk_;

TEST_F(ElGamalTest, EncDecWorks) {
  const Encryptor encryptor(pk_);
  const Decryptor decryptor(pk_, sk_);

  auto ct = encryptor.EncryptZero();
  ASSERT_EQ(decryptor.Decrypt(ct), MPInt());

  for (int i = 1; i < 10; ++i) {
    ct = encryptor.Encrypt(MPInt(i));
    ASSERT_EQ(decryptor.Decrypt(ct).Get<int>(), i);

    ct = encryptor.Encrypt(MPInt(-i));
    ASSERT_EQ(decryptor.Decrypt(ct).Get<int>(), -i);
  }

  ct = encryptor.Encrypt(pk_.PlaintextBound() - 1_mp);
  ASSERT_EQ(decryptor.Decrypt(ct), pk_.PlaintextBound() - 1_mp);

  // random test
  EXPECT_GE(pk_.PlaintextBound(), 1_mp << 16);
  yacl::parallel_for(0, 256, 1, [&](int64_t, int64_t) {
    MPInt p;
    MPInt::RandomLtN(pk_.PlaintextBound(), &p);

    auto ct = encryptor.Encrypt(p);
    ASSERT_EQ(decryptor.Decrypt(ct), p);
    ct = encryptor.Encrypt(-p);
    ASSERT_EQ(decryptor.Decrypt(ct), -p);
  });

  // too big to decrypt
  EXPECT_ANY_THROW(encryptor.Encrypt(pk_.PlaintextBound() + 1_mp));
}

TEST_F(ElGamalTest, CiphertextEvaluate) {
  const Encryptor encryptor(pk_);
  const Evaluator evaluator(pk_);
  const Decryptor decryptor(pk_, sk_);

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
  evaluator.Randomize(&res);
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

}  // namespace heu::lib::algorithms::elgamal::test
