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

#include "heu/library/algorithms/ou/key_generator.h"

#include "gtest/gtest.h"

namespace heu::lib::algorithms::ou::test {

class KeyGenTest : public ::testing::TestWithParam<size_t> {};

INSTANTIATE_TEST_SUITE_P(SubTest, KeyGenTest,
                         ::testing::Values(1024, 2048, 3072));

TEST_P(KeyGenTest, SubTest) {
  SecretKey sk;
  PublicKey pk;
  KeyGenerator::Generate(GetParam(), &sk, &pk);

  EXPECT_GE(pk.n_.BitCount(), GetParam());
  EXPECT_GE(pk.ch_table_->exp_max_bits, internal_params::kRandomBits3072);

  EXPECT_EQ(pk.cg_table_->exp_unit_expand, 1 << pk.cg_table_->exp_unit_bits);
  EXPECT_EQ(pk.cgi_table_->exp_unit_expand, 1 << pk.cgi_table_->exp_unit_bits);
  EXPECT_EQ(pk.ch_table_->exp_unit_expand, 1 << pk.ch_table_->exp_unit_bits);

  EXPECT_EQ(pk.cg_table_->exp_unit_expand, pk.cg_table_->exp_unit_mask + 1);
  EXPECT_EQ(pk.cgi_table_->exp_unit_expand, pk.cgi_table_->exp_unit_mask + 1);
  EXPECT_EQ(pk.ch_table_->exp_unit_expand, pk.ch_table_->exp_unit_mask + 1);
}

}  // namespace heu::lib::algorithms::ou::test
