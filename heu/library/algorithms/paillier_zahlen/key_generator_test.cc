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

#include "heu/library/algorithms/paillier_zahlen/key_generator.h"

#include "gtest/gtest.h"

namespace heu::lib::algorithms::paillier_z::test {

class KeyGenTest : public ::testing::TestWithParam<size_t> {};

INSTANTIATE_TEST_SUITE_P(SubTest, KeyGenTest,
                         ::testing::Values(1024, 2048, 3072));

TEST_P(KeyGenTest, KeyFieldTest) {
  PublicKey pk;
  SecretKey sk;
  KeyGenerator::Generate(GetParam(), &sk, &pk);
  EXPECT_GE((sk.p_ - sk.q_).Abs().BitCount(), GetParam() / 2 - 2);
  EXPECT_GE(pk.n_.BitCount(), GetParam());
  EXPECT_TRUE(pk.n_square_ == pk.n_ * pk.n_);
  EXPECT_TRUE(pk.n_ / MPInt::_2_ == pk.n_half_);
  EXPECT_TRUE(pk.hs_table_->exp_max_bits >= pk.key_size_ / 2);
  EXPECT_TRUE(pk.hs_table_->exp_max_bits < pk.key_size_ / 2 + MP_DIGIT_BIT);

  EXPECT_TRUE(sk.lambda_.IsPositive());
  EXPECT_TRUE(sk.mu_.IsPositive());
}

TEST_P(KeyGenTest, Serialize) {
  PublicKey pk;
  SecretKey sk;
  KeyGenerator::Generate(GetParam(), &sk, &pk);

  auto pk_buffer = pk.Serialize();
  auto sk_buffer = sk.Serialize();

  PublicKey pk2;
  pk2.Deserialize(yacl::ByteContainerView(pk_buffer));
  EXPECT_TRUE(pk.n_ == pk2.n_);
  EXPECT_TRUE(pk.n_square_ == pk2.n_square_);
  EXPECT_TRUE(pk.n_half_ == pk2.n_half_);
  EXPECT_TRUE(pk.h_s_ == pk2.h_s_);
  EXPECT_TRUE(pk.PlaintextBound() == pk2.PlaintextBound());

  SecretKey sk2;
  sk2.Deserialize(yacl::ByteContainerView(sk_buffer));
  EXPECT_TRUE(sk.lambda_ == sk2.lambda_);
  EXPECT_TRUE(sk.mu_ == sk2.mu_);
  EXPECT_TRUE(sk.mu_ == sk2.mu_);
  EXPECT_TRUE(sk.p_ == sk2.p_);
  EXPECT_TRUE(sk.q_ == sk2.q_);
  EXPECT_TRUE(sk.p_square_ == sk2.p_square_);
  EXPECT_TRUE(sk.q_square_ == sk2.q_square_);
  EXPECT_TRUE(sk.n_square_ == sk2.n_square_);
  EXPECT_TRUE(sk.q_square_inv_mul_q_square_ == sk2.q_square_inv_mul_q_square_);
  EXPECT_TRUE(sk.phi_p_square_ == sk2.phi_p_square_);
  EXPECT_TRUE(sk.phi_q_square_ == sk2.phi_q_square_);
}

}  // namespace heu::lib::algorithms::paillier_z::test
