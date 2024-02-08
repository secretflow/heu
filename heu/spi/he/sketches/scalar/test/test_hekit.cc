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

namespace heu::lib::spi::test {

class TestHeKit : public ::testing::Test {
 protected:
  std::unique_ptr<HeKit> kit_ = std::make_unique<DummyHeKit>();
};

TEST_F(TestHeKit, MetaWorks) {
  EXPECT_EQ(kit_->GetLibraryName(), "DummyLib");
  EXPECT_EQ(kit_->GetSchemaName(), "DummySchema");

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
  EXPECT_TRUE(pk.DataTypeIs<DummyPk>());
  EXPECT_EQ(pk, DummyPk("pk1"));

  auto sk = kit_->GetKey(HeKeyType::SecretKey);
  EXPECT_TRUE(sk.DataTypeIs<DummySk>());
  EXPECT_EQ(sk, DummySk("sk1"));

  auto rlk = kit_->GetKey(HeKeyType::RelinKeys);
  EXPECT_TRUE(rlk.DataTypeIs<DummyRlk>());
  EXPECT_EQ(rlk, DummyRlk("rlk1"));

  auto glk = kit_->GetKey(HeKeyType::GaloisKeys);
  EXPECT_TRUE(glk.DataTypeIs<DummyGlk>());
  EXPECT_EQ(glk, DummyGlk("glk1"));

  auto bsk = kit_->GetKey(HeKeyType::BootstrapKey);
  EXPECT_TRUE(bsk.DataTypeIs<DummyBsk>());
  EXPECT_EQ(bsk, DummyBsk("bsk1"));

  //===   I/O for keys   ===//
  EXPECT_EQ(kit_->GetItemManipulator()->Clone(pk), DummyPk("pk1"));
  EXPECT_EQ(kit_->GetItemManipulator()->Clone(sk), DummySk("sk1"));
  EXPECT_EQ(kit_->GetItemManipulator()->Clone(rlk), DummyRlk("rlk1"));
  EXPECT_EQ(kit_->GetItemManipulator()->Clone(glk), DummyGlk("glk1"));
  EXPECT_EQ(kit_->GetItemManipulator()->Clone(bsk), DummyBsk("bsk1"));

  EXPECT_EQ(kit_->GetItemManipulator()->ToString(pk), "dummy pk1");
  EXPECT_EQ(kit_->GetItemManipulator()->ToString(sk), "dummy sk1");
  EXPECT_EQ(kit_->GetItemManipulator()->ToString(rlk), "dummy rlk1");
  EXPECT_EQ(kit_->GetItemManipulator()->ToString(glk), "dummy glk1");
  EXPECT_EQ(kit_->GetItemManipulator()->ToString(bsk), "dummy bsk1");

  yacl::Buffer buf[2];
  for (const auto& key_type :
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
  auto manipulator = kit_->GetItemManipulator();

  EXPECT_EQ(manipulator->Clone(pt), DummyPt("1")) << manipulator->ToString(pt);
  EXPECT_EQ(manipulator->Clone(ct), DummyCt("Enc(pt1)"))
      << manipulator->ToString(ct);

  yacl::Buffer buf[2];
  buf[0] = manipulator->Serialize(pt);
  buf[1].resize(manipulator->Serialize(pt, nullptr, 0));
  EXPECT_EQ(manipulator->Serialize(pt, buf[1].data<uint8_t>(), buf[1].size()),
            buf[1].size());
  EXPECT_EQ(buf[0], buf[1]);

  auto pt_new = manipulator->Deserialize(buf[0]);
  EXPECT_EQ(pt_new, DummyPt("1"));

  buf[0] = manipulator->Serialize(ct);
  buf[1].resize(manipulator->Serialize(ct, nullptr, 0));
  EXPECT_EQ(manipulator->Serialize(ct, buf[1].data<uint8_t>(), buf[1].size()),
            buf[1].size());
  EXPECT_EQ(buf[0], buf[1]);

  auto ct_new = manipulator->Deserialize(buf[0]);
  EXPECT_EQ(ct_new, DummyCt("Enc(pt1)"));
}

TEST_F(TestHeKit, VecCtPtWorks) {
  auto pts = Item::Take(std::vector{DummyPt("1"), DummyPt("2"), DummyPt("3")},
                        ContentType::Plaintext);
  auto cts = kit_->GetEncryptor()->Encrypt(pts);
  auto manipulator = kit_->GetItemManipulator();

  ExpectItemEq<DummyPt>(manipulator->Clone(pts), {"1", "2", "3"});
  ExpectItemEq<DummyCt>(manipulator->Clone(cts),
                        {"Enc(pt1)", "Enc(pt2)", "Enc(pt3)"});

  yacl::Buffer buf[2];
  buf[0] = manipulator->Serialize(pts);
  buf[1].resize(manipulator->Serialize(pts, nullptr, 0));
  EXPECT_EQ(manipulator->Serialize(pts, buf[1].data<uint8_t>(), buf[1].size()),
            buf[1].size());
  EXPECT_EQ(buf[0], buf[1]);

  auto pts_new = manipulator->Deserialize(buf[0]);
  ExpectItemEq<DummyPt>(pts_new, {"1", "2", "3"});

  buf[0] = manipulator->Serialize(cts);
  buf[1].resize(manipulator->Serialize(cts, nullptr, 0));
  EXPECT_EQ(manipulator->Serialize(cts, buf[1].data<uint8_t>(), buf[1].size()),
            buf[1].size());
  EXPECT_EQ(buf[0], buf[1]);

  auto cts_new = manipulator->Deserialize(buf[0]);
  ExpectItemEq<DummyCt>(cts_new, {"Enc(pt1)", "Enc(pt2)", "Enc(pt3)"});
}

}  // namespace heu::lib::spi::test
