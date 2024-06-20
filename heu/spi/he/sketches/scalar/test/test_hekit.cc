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

#include <memory>

#include "gtest/gtest.h"

#include "heu/spi/he/sketches/scalar/test/dummy_hekit.h"

namespace heu::spi::test {

class TestHeKit : public ::testing::Test {
 protected:
  std::unique_ptr<HeKit> kit_ = std::make_unique<DummyHeKit>();
};

TEST_F(TestHeKit, MetaWorks) {
  EXPECT_EQ(kit_->GetLibraryName(), "DummyLib");
  EXPECT_EQ(kit_->GetSchema(), Schema::Unknown);

  EXPECT_NO_THROW(kit_->ToString());
  yacl::Buffer buf[2];
  buf[0] = kit_->Serialize();
  buf[1].resize(kit_->Serialize(nullptr, 0));
  EXPECT_EQ(kit_->Serialize(buf[1].data<uint8_t>(), buf[1].size()),
            buf[1].size());
  EXPECT_EQ(buf[0], buf[1]);
}

TEST_F(TestHeKit, AllKeyWorks) {
  //===   Meta query   ===//
  EXPECT_TRUE(kit_->GetPublicKey().DataTypeIs<DummyPk>());
  EXPECT_TRUE(kit_->GetSecretKey().DataTypeIs<DummySk>());

  auto pk = kit_->GetKey(HeKeyType::PublicKey);
  EXPECT_TRUE(pk.IsKey());
  EXPECT_TRUE(pk.DataTypeIs<DummyPk>());
  EXPECT_EQ(pk, DummyPk("pk1"));

  auto sk = kit_->GetKey(HeKeyType::SecretKey);
  EXPECT_TRUE(sk.IsKey());
  EXPECT_TRUE(sk.DataTypeIs<DummySk>());
  EXPECT_EQ(sk, DummySk("sk1"));

  auto rlk = kit_->GetKey(HeKeyType::RelinKeys);
  EXPECT_TRUE(rlk.IsKey());
  EXPECT_TRUE(rlk.DataTypeIs<DummyRlk>());
  EXPECT_EQ(rlk, DummyRlk("rlk1"));

  auto glk = kit_->GetKey(HeKeyType::GaloisKeys);
  EXPECT_TRUE(glk.IsKey());
  EXPECT_TRUE(glk.DataTypeIs<DummyGlk>());
  EXPECT_EQ(glk, DummyGlk("glk1"));

  auto bsk = kit_->GetKey(HeKeyType::BootstrapKey);
  EXPECT_TRUE(bsk.IsKey());
  EXPECT_TRUE(bsk.DataTypeIs<DummyBsk>());
  EXPECT_EQ(bsk, DummyBsk("bsk1"));

  //===   I/O for keys   ===//
  EXPECT_ANY_THROW((kit_->GetItemTool()->Clone(pk), DummyPk("pk1")));
  EXPECT_ANY_THROW((kit_->GetItemTool()->Clone(sk), DummySk("sk1")));
  EXPECT_ANY_THROW((kit_->GetItemTool()->Clone(rlk), DummyRlk("rlk1")));
  EXPECT_ANY_THROW((kit_->GetItemTool()->Clone(glk), DummyGlk("glk1")));
  EXPECT_ANY_THROW((kit_->GetItemTool()->Clone(bsk), DummyBsk("bsk1")));

  EXPECT_EQ(kit_->GetItemTool()->ToString(pk), "PublicKey[id=pk1]");
  EXPECT_EQ(kit_->GetItemTool()->ToString(sk), "SecretKey[id=sk1]");
  EXPECT_EQ(kit_->GetItemTool()->ToString(rlk), "RelinKeys[id=rlk1]");
  EXPECT_EQ(kit_->GetItemTool()->ToString(glk), "GaloisKeys[id=glk1]");
  EXPECT_EQ(kit_->GetItemTool()->ToString(bsk), "BootstrapKey[id=bsk1]");

  yacl::Buffer buf[2];
  for (const auto &key_type :
       {HeKeyType::PublicKey, HeKeyType::SecretKey, HeKeyType::RelinKeys,
        HeKeyType::GaloisKeys, HeKeyType::BootstrapKey}) {
    buf[0] = kit_->Serialize(key_type);
    buf[1].resize(kit_->Serialize(key_type, nullptr, 0));
    EXPECT_EQ(kit_->Serialize(key_type, buf[1].data<uint8_t>(), buf[1].size()),
              buf[1].size());
    EXPECT_EQ(buf[0], buf[1]);
  }
}

TEST_F(TestHeKit, ScalarCtPtWorks) {
  // scalar case
  Item pt = {DummyPt("1"), ContentType::Plaintext};
  auto ct = kit_->GetEncryptor()->Encrypt(pt);
  auto itool = kit_->GetItemTool();

  EXPECT_EQ(itool->Clone(pt), DummyPt("1")) << itool->ToString(pt);
  EXPECT_EQ(itool->Clone(ct), DummyCt("Enc(pt1)")) << itool->ToString(ct);

  yacl::Buffer buf[2];
  buf[0] = itool->Serialize(pt);
  buf[1].resize(itool->Serialize(pt, nullptr, 0));
  EXPECT_EQ(itool->Serialize(pt, buf[1].data<uint8_t>(), buf[1].size()),
            buf[1].size());
  EXPECT_EQ(buf[0], buf[1]);

  auto pt_new = itool->Deserialize(buf[0]);
  EXPECT_EQ(pt_new, DummyPt("1"));

  buf[0] = itool->Serialize(ct);
  buf[1].resize(itool->Serialize(ct, nullptr, 0));
  EXPECT_EQ(itool->Serialize(ct, buf[1].data<uint8_t>(), buf[1].size()),
            buf[1].size());
  EXPECT_EQ(buf[0], buf[1]);

  auto ct_new = itool->Deserialize(buf[0]);
  EXPECT_EQ(ct_new, DummyCt("Enc(pt1)"));
}

TEST_F(TestHeKit, VecCtPtWorks) {
  auto pts = Item::Take(std::vector{DummyPt("1"), DummyPt("2"), DummyPt("3")},
                        ContentType::Plaintext);
  auto cts = kit_->GetEncryptor()->Encrypt(pts);
  auto itool = kit_->GetItemTool();

  ExpectItemEq<DummyPt>(itool->Clone(pts), {"1", "2", "3"});
  ExpectItemEq<DummyCt>(itool->Clone(cts),
                        {"Enc(pt1)", "Enc(pt2)", "Enc(pt3)"});

  yacl::Buffer buf[2];
  buf[0] = itool->Serialize(pts);
  buf[1].resize(itool->Serialize(pts, nullptr, 0));
  EXPECT_EQ(itool->Serialize(pts, buf[1].data<uint8_t>(), buf[1].size()),
            buf[1].size());
  EXPECT_EQ(buf[0], buf[1]);

  auto pts_new = itool->Deserialize(buf[0]);
  ExpectItemEq<DummyPt>(pts_new, {"1", "2", "3"});

  buf[0] = itool->Serialize(cts);
  buf[1].resize(itool->Serialize(cts, nullptr, 0));
  EXPECT_EQ(itool->Serialize(cts, buf[1].data<uint8_t>(), buf[1].size()),
            buf[1].size());
  EXPECT_EQ(buf[0], buf[1]);

  auto cts_new = itool->Deserialize(buf[0]);
  ExpectItemEq<DummyCt>(cts_new, {"Enc(pt1)", "Enc(pt2)", "Enc(pt3)"});
}

}  // namespace heu::spi::test
