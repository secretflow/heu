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

#include "gtest/gtest.h"

#include "heu/library/phe/encoding/encoding.h"
#include "heu/library/phe/phe.h"

namespace heu::lib::phe::test {

class EvaluatorTest : public ::testing::TestWithParam<SchemaType> {
 protected:
  HeKit he_kit_ = HeKit(GetParam());
  PlainEncoder edr = he_kit_.GetEncoder<PlainEncoder>(1);
};

INSTANTIATE_TEST_SUITE_P(Schema, EvaluatorTest,
                         ::testing::ValuesIn(GetAllSchema()));

TEST_P(EvaluatorTest, Evaluate) {
  auto encryptor = he_kit_.GetEncryptor();
  auto evaluator = he_kit_.GetEvaluator();
  auto decryptor = he_kit_.GetDecryptor();

  auto ct0 = encryptor->Encrypt(edr.Encode(-12345));
  evaluator->Randomize(&ct0);
  EXPECT_EQ(decryptor->Decrypt(ct0).GetValue<int64_t>(), -12345);

  auto ct1 = evaluator->Negate(ct0);
  EXPECT_EQ(decryptor->Decrypt(ct1).GetValue<int64_t>(), 12345);

  // ADD //
  ct1 = evaluator->Add(ct0, ct0);
  EXPECT_EQ(decryptor->Decrypt(ct1).GetValue<int64_t>(), -12345 * 2);

  ct1 = evaluator->Add(ct0, edr.Encode((345)));
  EXPECT_EQ(decryptor->Decrypt(ct1).GetValue<int64_t>(), -12345 + 345);

  if (he_kit_.GetPublicKey()->PlaintextBound().BitCount() < 64) {
    GTEST_SKIP() << fmt::format("skip {}", GetParam());
  }

  // ADD - int64
  auto encoder = PlainEncoder(GetParam(), std::numeric_limits<int64_t>::max());
  auto imax = std::numeric_limits<int64_t>::max();
  auto ct_max = encryptor->Encrypt(encoder.Encode(imax - 1));
  ct1 = evaluator->Add(ct_max, encoder.Encode(1));
  EXPECT_EQ(encoder.Decode<int64_t>(decryptor->Decrypt(ct1)), imax);

  // SUB //
  ct1 = evaluator->Sub(ct0, ct0);
  EXPECT_EQ(decryptor->Decrypt(ct1).GetValue<int32_t>(), 0);

  ct1 = evaluator->Sub(ct0, edr.Encode((345)));
  EXPECT_EQ(decryptor->Decrypt(ct1).GetValue<int64_t>(), -12345 - 345);

  ct1 = evaluator->Sub(edr.Encode((789)), ct0);
  EXPECT_EQ(decryptor->Decrypt(ct1).GetValue<int64_t>(), 12345 + 789);

  // SUB - int64
  auto umax = std::numeric_limits<uint64_t>::max();
  auto ct_umax = encryptor->Encrypt(encoder.Encode(umax));
  ct1 = evaluator->Sub(ct_umax, encoder.Encode(1));
  EXPECT_EQ(encoder.Decode<uint64_t>(decryptor->Decrypt(ct1)), umax - 1);

  // MUL //
  ct1 = evaluator->Mul(ct0, edr.Encode((0)));
  EXPECT_EQ(decryptor->Decrypt(ct1).GetValue<int64_t>(), -12345 * 0);

  ct1 = evaluator->Mul(ct0, edr.Encode((1)));
  EXPECT_EQ(decryptor->Decrypt(ct1).GetValue<int64_t>(), -12345 * 1);

  ct1 = evaluator->Mul(ct0, edr.Encode((2)));
  EXPECT_EQ(decryptor->Decrypt(ct1).GetValue<int64_t>(), -12345 * 2);

  if (GetParam() == SchemaType::DGK) {
    GTEST_SKIP() << "Plaintext range is not enough, Skip DGK";
  }

  ct1 = evaluator->Mul(ct0, edr.Encode((10)));
  EXPECT_EQ(decryptor->Decrypt(ct1).GetValue<int64_t>(), -12345 * 10);
}

TEST_P(EvaluatorTest, EvaluateInplace) {
  auto encryptor = he_kit_.GetEncryptor();
  auto evaluator = he_kit_.GetEvaluator();
  auto decryptor = he_kit_.GetDecryptor();

  Plaintext pt0 = edr.Encode(9876);
  Plaintext pt1 = edr.Encode(1234);
  auto ct0 = encryptor->Encrypt(pt0);
  auto ct1 = encryptor->Encrypt(pt1);
  evaluator->Randomize(&ct0);
  EXPECT_EQ(decryptor->Decrypt(ct0).GetValue<int64_t>(), 9876);

  evaluator->NegateInplace(&ct1);
  pt1.NegateInplace();
  EXPECT_EQ(decryptor->Decrypt(ct1), pt1);

  // ADD //
  evaluator->AddInplace(&ct0, ct1);
  pt0 += pt1;
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);

  evaluator->AddInplace(&ct0, edr.Encode(963));
  pt0 += edr.Encode((963));
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);

  evaluator->AddInplace(&ct0, edr.Encode(-741));
  pt0 += edr.Encode(-741);
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);

  // SUB //
  evaluator->SubInplace(&ct0, ct1);
  pt0 -= pt1;
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);

  evaluator->SubInplace(&ct0, edr.Encode(852));
  pt0 -= edr.Encode(852);
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);

  if (GetParam() == SchemaType::DGK) {
    GTEST_SKIP() << "Plaintext range is not enough, Skip DGK";
  }
  // MUL //
  evaluator->MulInplace(&ct0, edr.Encode(10));
  pt0 *= edr.Encode(10);
  EXPECT_EQ(decryptor->Decrypt(ct0), pt0);
}

}  // namespace heu::lib::phe::test
