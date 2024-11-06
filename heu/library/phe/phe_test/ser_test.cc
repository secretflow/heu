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

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "heu/library/phe/encoding/encoding.h"
#include "heu/library/phe/phe.h"

namespace heu::lib::phe::test {

class SerTest : public ::testing::TestWithParam<SchemaType> {
 protected:
  HeKit he_kit_ = HeKit(GetParam());
  PlainEncoder edr_ = he_kit_.GetEncoder<PlainEncoder>(1);
};

INSTANTIATE_TEST_SUITE_P(Schema, SerTest, ::testing::ValuesIn(GetAllSchema()));

TEST_P(SerTest, KeySerialize) {
  // make sure key has content
  auto sk_str = he_kit_.GetSecretKey()->ToString();
  EXPECT_GT(sk_str.length(), 30) << sk_str;
  auto pk_str = he_kit_.GetPublicKey()->ToString();
  EXPECT_GT(pk_str.length(), 30) << pk_str;

  // test pk
  auto buffer_pk = he_kit_.GetPublicKey()->Serialize();
  EXPECT_NE(*he_kit_.GetPublicKey(), PublicKey());
  EXPECT_NE(*he_kit_.GetPublicKey(), PublicKey(he_kit_.GetSchemaType()));
  PublicKey pk;
  pk.Deserialize(buffer_pk);
  EXPECT_EQ(*he_kit_.GetPublicKey(), pk);

  // test sk
  auto buffer_sk = he_kit_.GetSecretKey()->Serialize();
  EXPECT_NE(*he_kit_.GetSecretKey(), SecretKey());
  EXPECT_NE(*he_kit_.GetSecretKey(), SecretKey(he_kit_.GetSchemaType()));
  SecretKey sk;
  sk.Deserialize(buffer_sk);
  EXPECT_EQ(*he_kit_.GetSecretKey(), sk);

  // recover HeKit from pk/sk
  auto kit2 = HeKit(buffer_pk, buffer_sk);
  auto kit3 = HeKit(he_kit_.GetPublicKey(), he_kit_.GetSecretKey());
  ASSERT_EQ(*kit2.GetPublicKey(), *kit3.GetPublicKey());
  ASSERT_EQ(*kit2.GetSecretKey(), *kit3.GetSecretKey());
  auto pt = edr_.Encode(4321);
  auto ct = he_kit_.GetEncryptor()->Encrypt(pt);
  EXPECT_EQ(kit2.GetDecryptor()->Decrypt(ct), pt);
  EXPECT_EQ(kit3.GetDecryptor()->Decrypt(ct), pt);
}

TEST_P(SerTest, VarSerialize) {
  // test serialize plaintext
  auto clear = he_kit_.GetSchemaType() == SchemaType::DGK ? -9632 : -963258741;
  auto plain = Plaintext(he_kit_.GetSchemaType(), clear);
  EXPECT_NE(plain, Plaintext());
  EXPECT_NE(plain, Plaintext(he_kit_.GetSchemaType()));
  EXPECT_NE(plain, Plaintext(he_kit_.GetSchemaType(), -clear));
  EXPECT_EQ(plain, Plaintext(he_kit_.GetSchemaType(), clear));
  auto buffer = plain.Serialize();
  Plaintext pt2;
  pt2.Deserialize(buffer);
  EXPECT_TRUE(pt2.IsCompatible(he_kit_.GetSchemaType()));
  EXPECT_EQ(plain, pt2);

  // test serialize ciphertext
  auto ct0 = he_kit_.GetEncryptor()->Encrypt(plain);
  EXPECT_GE(ct0.ToString().length(), 10) << ct0.ToString();
  EXPECT_NE(ct0, Ciphertext());
  EXPECT_NE(ct0, Ciphertext(he_kit_.GetSchemaType()));
  buffer = ct0.Serialize();
  EXPECT_GT(buffer.size(), sizeof(size_t)) << buffer;

  Ciphertext ct1;
  ct1.Deserialize(buffer);
  EXPECT_TRUE(ct1.IsCompatible(he_kit_.GetSchemaType()));
  EXPECT_EQ(ct0, ct1);
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(ct1), plain);

  // test serialize public key
  auto buffer_pk = he_kit_.GetPublicKey()->Serialize();
  DestinationHeKit server(buffer_pk);
  server.GetEvaluator()->AddInplace(&ct1, edr_.Encode(666));
  server.GetEvaluator()->Randomize(&ct1);
  buffer = ct1.Serialize();

  // send back to client
  Ciphertext ct2;
  ct2.Deserialize(buffer);
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(ct1), plain + edr_.Encode(666));
}

}  // namespace heu::lib::phe::test
