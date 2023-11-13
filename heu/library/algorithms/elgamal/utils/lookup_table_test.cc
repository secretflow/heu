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

#include "heu/library/algorithms/elgamal/utils/lookup_table.h"

#include "gtest/gtest.h"
#include "yacl/utils/parallel.h"

namespace heu::lib::algorithms::elgamal::test {

class LookupTableTest : public testing::Test {
 protected:
  std::shared_ptr<yacl::crypto::EcGroup> ec_ =
      yacl::crypto::EcGroupFactory::Instance().Create("ed25519");
};

TEST_F(LookupTableTest, SimpleWorks) {
  // Test LookupTable is movable
  LookupTable tmp;
  tmp.Init(ec_);
  LookupTable table = std::move(tmp);

  // exist
  for (int i = -100; i < 100; ++i) {
    EXPECT_EQ(table.Search(ec_->MulBase(MPInt(i))), i);
  }

  // not exist
  EXPECT_ANY_THROW(table.Search(ec_->MulBase(1_mp << 128)));
}

TEST_F(LookupTableTest, MinMaxSearch) {
  LookupTable table;
  table.Init(ec_);

  auto max_v = table.MaxSupportedValue();
  auto point = ec_->MulBase(max_v);
  EXPECT_EQ(table.Search(point), max_v.Get<int64_t>());

  ec_->NegateInplace(&point);
  EXPECT_EQ(table.Search(point), -max_v.Get<int64_t>());
}

}  // namespace heu::lib::algorithms::elgamal::test
