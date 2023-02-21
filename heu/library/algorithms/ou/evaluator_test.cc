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

#include <string>

#include "gtest/gtest.h"

#include "heu/library/algorithms/ou/ou.h"

namespace heu::lib::algorithms::ou::test {

class NegateInplaceTest : public ::testing::TestWithParam<int64_t> {
 protected:
  static void SetUpTestSuite() { KeyGenerator::Generate(2048, &sk_, &pk_); }

  static SecretKey sk_;
  static PublicKey pk_;
};

SecretKey NegateInplaceTest::sk_;
PublicKey NegateInplaceTest::pk_;

INSTANTIATE_TEST_SUITE_P(
    FullRange, NegateInplaceTest,
    ::testing::Values(0, 1, -1, 2, -2, 4, -4, 1024, -1024, 100000, -100000,
                      std::numeric_limits<int64_t>::max() / 2,
                      -(std::numeric_limits<int64_t>::max() / 2),
                      std::numeric_limits<int64_t>::max(),
                      std::numeric_limits<int64_t>::min()));

TEST_P(NegateInplaceTest, TestNegate) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  Ciphertext ct0;
  MPInt plain;
  int64_t in = GetParam();

  ct0 = encryptor.Encrypt(MPInt(in));
  evaluator.NegateInplace(&ct0);
  decryptor.Decrypt(ct0, &plain);
  EXPECT_EQ(plain.Get<int64_t>(), -in);
}

TEST_P(NegateInplaceTest, CriticalValue) {
  Encryptor encryptor(pk_);
  Evaluator evaluator(pk_);
  Decryptor decryptor(pk_, sk_);

  int64_t in = GetParam();
  MPInt m(in);
  Ciphertext ct = encryptor.Encrypt(m);
  Ciphertext ct0 = evaluator.Mul(ct, MPInt(0));
  Ciphertext ct1 = evaluator.Mul(ct, MPInt(1));
  Ciphertext ct2 = evaluator.Mul(ct, MPInt(-1));
  Ciphertext ct3 = evaluator.Mul(ct, MPInt(2));
  Ciphertext ct4 = evaluator.Mul(ct, MPInt(-2));

  MPInt res;
  decryptor.Decrypt(ct0, &res);
  EXPECT_EQ(res.Get<int64_t>(), 0);
  decryptor.Decrypt(ct1, &res);
  EXPECT_EQ(res.Get<int64_t>(), in);
  decryptor.Decrypt(ct2, &res);
  EXPECT_EQ(res.Get<int64_t>(), -in);
  decryptor.Decrypt(ct3, &res);
  EXPECT_EQ(res.Get<int64_t>(), in * 2);
  decryptor.Decrypt(ct4, &res);
  EXPECT_EQ(res.Get<int64_t>(), -in * 2);
}

}  // namespace heu::lib::algorithms::ou::test
