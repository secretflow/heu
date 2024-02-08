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

#include "heu/spi/he/item.h"

#include <utility>
#include <vector>

#include "gtest/gtest.h"

namespace heu::lib::spi::test {

class DummyPt {};

TEST(HeItemTest, BasicWorks) {
  std::vector<DummyPt> pts;

  auto a = Item::Ref(pts, ContentType::Plaintext);
  EXPECT_FALSE(a.IsCiphertext());
  EXPECT_TRUE(a.IsPlaintext());
  EXPECT_TRUE(a.IsArray());
  EXPECT_FALSE(a.IsReadOnly());
  EXPECT_TRUE(a.IsView());

  const std::vector<DummyPt>& pts2 = pts;
  a = Item::Ref(pts2, ContentType::Plaintext);
  EXPECT_FALSE(a.IsCiphertext());
  EXPECT_TRUE(a.IsPlaintext());
  EXPECT_TRUE(a.IsArray());
  EXPECT_TRUE(a.IsReadOnly());
  EXPECT_TRUE(a.IsView());

  a = Item::Take(std::move(pts), ContentType::Plaintext);
  EXPECT_FALSE(a.IsCiphertext());
  EXPECT_TRUE(a.IsPlaintext());
  EXPECT_TRUE(a.IsArray());
  EXPECT_FALSE(a.IsReadOnly());
  EXPECT_FALSE(a.IsView());
  // check vector is moved
  EXPECT_EQ(pts.size(), 0);
}

TEST(HeItemTest, MaskAsWorks) {
  EXPECT_EQ((int)ContentType::PublicKey, (int)HeKeyType::PublicKey);
  EXPECT_EQ((int)ContentType::SecretKey, (int)HeKeyType::SecretKey);
  EXPECT_EQ((int)ContentType::RelinKeys, (int)HeKeyType::RelinKeys);
  EXPECT_EQ((int)ContentType::GaloisKeys, (int)HeKeyType::GaloisKeys);
  EXPECT_EQ((int)ContentType::BootstrapKey, (int)HeKeyType::BootstrapKey);

  Item item = {"hello", ContentType::Others};
  item.MarkAsPlaintext();
  EXPECT_TRUE(item.IsPlaintext());
  EXPECT_EQ(item.GetContentType(), ContentType::Plaintext);
  item.MarkAsCiphertext();
  EXPECT_TRUE(item.IsCiphertext());
  EXPECT_EQ(item.GetContentType(), ContentType::Ciphertext);

  item.MarkAs(ContentType::PublicKey);
  EXPECT_EQ(item.GetContentType(), ContentType::PublicKey);
  item.MarkAs(ContentType::SecretKey);
  EXPECT_EQ(item.GetContentType(), ContentType::SecretKey);
  item.MarkAs(ContentType::RelinKeys);
  EXPECT_EQ(item.GetContentType(), ContentType::RelinKeys);
  item.MarkAs(ContentType::GaloisKeys);
  EXPECT_EQ(item.GetContentType(), ContentType::GaloisKeys);
  item.MarkAs(ContentType::BootstrapKey);
  EXPECT_EQ(item.GetContentType(), ContentType::BootstrapKey);
}

}  // namespace heu::lib::spi::test
