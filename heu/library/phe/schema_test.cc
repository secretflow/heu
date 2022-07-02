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
#include "heu/library/phe/schema.h"

#include "gtest/gtest.h"

#include "heu/library/phe/phe.h"

namespace heu::lib::phe::test {
class PheTest : public ::testing::Test {};

// Test: Make sure `SchemaType` is in the same order as `HE_FOR_EACH`
TEST_F(PheTest, SchemaEqualsMacro) {
  Ciphertext ciphertext0(SchemaType::None);
  ciphertext0.visit([](auto obj) {
    bool same =
        (std::is_same<decltype(obj), algorithms::mock::Ciphertext>::value);
    EXPECT_TRUE(same);
  });

  Ciphertext ciphertext2(SchemaType::FPaillier);
  ciphertext2.visit([](auto obj) {
    bool same = (std::is_same<decltype(obj),
                              algorithms::paillier_f::Ciphertext>::value);
    EXPECT_TRUE(same);
  });

  Ciphertext ciphertext3(SchemaType::ZPaillier);
  ciphertext3.visit([](auto obj) {
    bool same = (std::is_same<decltype(obj),
                              algorithms::paillier_z::Ciphertext>::value);
    EXPECT_TRUE(same);
  });
};

TEST_F(PheTest, SchemaParse) {
  EXPECT_EQ(ParseSchemaType("mock"), SchemaType::None);
  EXPECT_EQ(ParseSchemaType("plain"), SchemaType::None);
  EXPECT_EQ(ParseSchemaType("paillier"), SchemaType::ZPaillier);
  EXPECT_EQ(ParseSchemaType("fpaillier"), SchemaType::FPaillier);
  EXPECT_THROW(ParseSchemaType("abc"), yasl::RuntimeError);

  EXPECT_EQ(SchemaToString(SchemaType::None), "none");
  EXPECT_EQ(SchemaToString(SchemaType::ZPaillier), "z-paillier");
  EXPECT_EQ(SchemaToString(SchemaType::FPaillier), "f-paillier");
}

}  // namespace heu::lib::phe::test
