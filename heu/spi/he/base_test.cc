// Copyright 2024 Ant Group Co., Ltd.
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

#include "heu/spi/he/base.h"

#include <utility>
#include <vector>

#include "gtest/gtest.h"

namespace heu::lib::spi::test {

class Pt {};

TEST(BaseTest, Basic) {
  std::vector<Pt> pts;

  auto a = Item::Ref(pts, ItemType::Plaintext);
  EXPECT_FALSE(a.IsCiphertext());
  EXPECT_TRUE(a.IsPlaintext());
  EXPECT_TRUE(a.IsArray());
  EXPECT_FALSE(a.IsReadOnly());
  EXPECT_TRUE(a.IsView());

  const std::vector<Pt>& pts2 = pts;
  a = Item::Ref(pts2, ItemType::Plaintext);
  EXPECT_FALSE(a.IsCiphertext());
  EXPECT_TRUE(a.IsPlaintext());
  EXPECT_TRUE(a.IsArray());
  EXPECT_TRUE(a.IsReadOnly());
  EXPECT_TRUE(a.IsView());

  a = Item::Take(std::move(pts), ItemType::Plaintext);
  EXPECT_FALSE(a.IsCiphertext());
  EXPECT_TRUE(a.IsPlaintext());
  EXPECT_TRUE(a.IsArray());
  EXPECT_FALSE(a.IsReadOnly());
  EXPECT_FALSE(a.IsView());
  // check vector is moved
  EXPECT_EQ(pts.size(), 0);
}

}  // namespace heu::lib::spi::test
