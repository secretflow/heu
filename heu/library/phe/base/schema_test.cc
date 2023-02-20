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

#include "heu/library/phe/base/schema.h"

#include "fmt/ranges.h"
#include "gtest/gtest.h"

#include "heu/library/phe/base/serializable_types.h"

namespace heu::lib::phe::test {

class SchemaTest : public ::testing::Test {};

// Test: Make sure `SchemaType` is in the same order as `HE_FOR_EACH`
TEST_F(SchemaTest, SchemaEqualsMacro) {
  Ciphertext ciphertext0(SchemaType::Mock);
  ciphertext0.Visit([](auto obj) {
    EXPECT_TRUE((std::is_same_v<decltype(obj), algorithms::mock::Ciphertext>));
  });

  Ciphertext ciphertext1(SchemaType::OU);
  ciphertext1.Visit([](auto obj) {
    EXPECT_TRUE((std::is_same_v<decltype(obj), algorithms::ou::Ciphertext>));
  });

  Ciphertext ciphertext2(SchemaType::FPaillier);
  ciphertext2.Visit([](auto obj) {
    EXPECT_TRUE(
        (std::is_same_v<decltype(obj), algorithms::paillier_f::Ciphertext>));
  });

  Ciphertext ciphertext3(SchemaType::ZPaillier);
  ciphertext3.Visit([](auto obj) {
    EXPECT_TRUE(
        (std::is_same_v<decltype(obj), algorithms::paillier_z::Ciphertext>));
  });
};

// This test cannot replace SchemaTest.SchemaEqualsMacro
// Since the IsCompatible() method is based on HE_FOR_EACH macro too.
TEST_F(SchemaTest, HeMacroWorks) {
#define TEST_NAMESPACE_LIST(ns) \
  Ciphertext(ns::Ciphertext()).IsCompatible(static_cast<SchemaType>(i++))

  int i = 0;
  std::vector<bool> res = {HE_FOR_EACH(TEST_NAMESPACE_LIST)};
  ASSERT_EQ(res.size(), GetAllSchema().size())
      << "HE_FOR_EACH not equal to SchemaType";
  for (const auto& item : res) {
    ASSERT_TRUE(item);
  }
}

TEST_F(SchemaTest, AliasesUnique) {
  std::unordered_set<std::string> alias_set;
  int count = 0;
  for (const auto& schema : GetAllSchema()) {
    for (const auto& alias : GetSchemaAliases(schema)) {
      ++count;
      ASSERT_TRUE(alias_set.count(alias) == 0)
          << fmt::format("all schema: {}, alias_set: {}, dup={}",
                         GetAllSchema(), alias_set, alias);
      alias_set.insert(alias);
    }
  }

  ASSERT_EQ(alias_set.size(), count);
}

TEST_F(SchemaTest, SelectSchema) {
  ASSERT_EQ(SelectSchemas("paillier", true).size(), 1);
  ASSERT_GE(SelectSchemas("paillier", false).size(), 2);
  ASSERT_GE(SelectSchemas("paillier.+", true).size(), 2);
}

TEST_F(SchemaTest, SchemaParse) {
  EXPECT_EQ(ParseSchemaType("mock"), SchemaType::Mock);
  EXPECT_EQ(ParseSchemaType("plain"), SchemaType::Mock);
  EXPECT_EQ(ParseSchemaType("ou"), SchemaType::OU);
  EXPECT_EQ(ParseSchemaType("paillier"), SchemaType::ZPaillier);
  EXPECT_EQ(ParseSchemaType("fpaillier"), SchemaType::FPaillier);
  EXPECT_THROW(ParseSchemaType("abc"), yacl::RuntimeError);

  EXPECT_EQ(SchemaToString(SchemaType::Mock), "Mock");
  EXPECT_EQ(SchemaToString(SchemaType::OU), "OU");
  EXPECT_EQ(SchemaToString(SchemaType::ZPaillier), "ZPaillier");
  EXPECT_EQ(SchemaToString(SchemaType::FPaillier), "FPaillier");
}

}  // namespace heu::lib::phe::test
