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

class EncryptorTest : public ::testing::TestWithParam<SchemaType> {
 protected:
  HeKit he_kit_ = HeKit(GetParam());
  PlainEncoder edr_ = he_kit_.GetEncoder<PlainEncoder>(1);
};

INSTANTIATE_TEST_SUITE_P(Schema, EncryptorTest,
                         ::testing::ValuesIn(GetAllSchema()));

// This UT has been migrated to SPI and will be deleted later
TEST_P(EncryptorTest, EncryptZero) {
  auto ct0 = he_kit_.GetEncryptor()->EncryptZero();
  Plaintext plain;

  he_kit_.GetDecryptor()->Decrypt(ct0, &plain);
  ASSERT_EQ(plain.GetValue<int32_t>(), 0);

  he_kit_.GetEvaluator()->AddInplace(&ct0,
                                     he_kit_.GetEncryptor()->EncryptZero());
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0).GetValue<int32_t>(), 0);

  he_kit_.GetEvaluator()->SubInplace(&ct0,
                                     he_kit_.GetEncryptor()->EncryptZero());
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0).GetValue<int32_t>(), 0);

  auto p = he_kit_.GetEvaluator()->Sub(edr_.Encode(123), ct0);
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(p), edr_.Encode(123));

  // 0 * 0
  he_kit_.GetEvaluator()->MulInplace(&ct0, edr_.Encode(0));
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0).GetValue<int32_t>(), 0);

  he_kit_.GetEvaluator()->MulInplace(&ct0, edr_.Encode(123456));
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0).GetValue<int32_t>(), 0);

  he_kit_.GetEvaluator()->MulInplace(&ct0, edr_.Encode(-123456));
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0).GetValue<int32_t>(), 0);

  he_kit_.GetEvaluator()->NegateInplace(&ct0);
  ASSERT_EQ(he_kit_.GetDecryptor()->Decrypt(ct0).GetValue<int32_t>(), 0);
}

TEST_P(EncryptorTest, MinMaxEnc) {
  auto encryptor = he_kit_.GetEncryptor();
  auto decryptor = he_kit_.GetDecryptor();

  auto plain = he_kit_.GetPublicKey()->PlaintextBound() + edr_.Encode(1);
  EXPECT_THROW(encryptor->Encrypt(plain), std::exception);  // too big

  plain.NegateInplace();
  EXPECT_THROW(encryptor->Encrypt(plain), std::exception);  // too small

  plain = he_kit_.GetPublicKey()->PlaintextBound();  // max
  Ciphertext ct0 = encryptor->Encrypt(plain);
  Plaintext plain_dec = decryptor->Decrypt(ct0);
  EXPECT_EQ(plain, plain_dec);

  plain.NegateInplace();  // -max
  ct0 = encryptor->Encrypt(plain);
  decryptor->Decrypt(ct0, &plain_dec);
  EXPECT_EQ(plain, plain_dec) << he_kit_.GetPublicKey()->ToString();

  plain -= edr_.Encode(1);
  EXPECT_THROW(encryptor->Encrypt(plain), std::exception);  // too small
}

}  // namespace heu::lib::phe::test
