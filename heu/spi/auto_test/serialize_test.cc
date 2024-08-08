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

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "heu/spi/auto_test/tool.h"
#include "heu/spi/he/he.h"

namespace heu::spi::test {

template <typename... T>
std::shared_ptr<Encoder> TryGetEncoder(const std::shared_ptr<HeKit> &kit,
                                       std::string method,
                                       const T &...encoder_args) {
  if (kit->GetFeatureSet() == FeatureSet::ApproxFHE && method == "plain") {
    SPDLOG_WARN(
        "CKKS-like schemas do not support plain encoder, use batch instead");
    method = "batch";
  }

  return kit->GetEncoder(ArgEncodingMethod = method, encoder_args...);
}

class SerializeTest : public testing::TestWithParam<std::shared_ptr<HeKit>> {
  void SetUp() override {
    kit_ = GetParam();
    // test ToString(). don't remove this line
    fmt::println("Testing {}", *kit_);

    itool_ = kit_->GetItemTool();
    enc_ = kit_->GetEncryptor();
    eval_ = kit_->GetWordEvaluator();
    dec_ = kit_->GetDecryptor();
  }

 protected:
  std::shared_ptr<HeKit> kit_;

  std::shared_ptr<ItemTool> itool_;
  std::shared_ptr<Encryptor> enc_;
  std::shared_ptr<WordEvaluator> eval_;
  std::shared_ptr<Decryptor> dec_;
};

INSTANTIATE_TEST_SUITE_P(HeCollection, SerializeTest,
                         SelectHeKitsForTest({FeatureSet::AdditivePHE,
                                              FeatureSet::WordFHE,
                                              FeatureSet::ApproxFHE}),
                         GenTestName<SerializeTest>);

TEST_P(SerializeTest, PtCtWorks) {
  // get meta info
  EXPECT_NO_THROW(kit_->ListKeyParams(HeKeyType::PublicKey));
  EXPECT_NO_THROW(kit_->ListKeyParams(HeKeyType::SecretKey));
  // test key ToString()
  EXPECT_GT(itool_->ToString(kit_->GetPublicKey()).size(), 0);
  EXPECT_GT(itool_->ToString(kit_->GetSecretKey()).size(), 0);

  auto edr = kit_->GetEncoder();
  std::vector<int64_t> pts_vec = {400, 700, 999, 0, 1,   -1,    2,
                                  -2,  3,   7,   8, 100, -1000, 1024};
  const auto pts = edr->Encode(pts_vec);
  EXPECT_TRUE(pts.IsPlaintext());

  std::string str = itool_->ToString(pts);
  EXPECT_GT(str.size(), 0);
  fmt::println("Pts array is {}", str);
  auto pts_buf = kit_->GetItemTool()->Serialize(pts);
  ASSERT_EQ(pts_buf.size(), kit_->GetItemTool()->Serialize(pts, nullptr, 0));
  Item new_pts = kit_->GetItemTool()->Deserialize(pts_buf);
  EXPECT_TRUE(itool_->Equal(pts, new_pts));

  const auto cts = enc_->Encrypt(pts);
  ASSERT_TRUE(cts.IsCiphertext());
  str = itool_->ToString(cts);
  EXPECT_GT(str.size(), 0);

  auto cts_buf = kit_->GetItemTool()->Serialize(cts);
  ASSERT_EQ(cts_buf.size(), kit_->GetItemTool()->Serialize(cts, nullptr, 0));
  Item new_cts = kit_->GetItemTool()->Deserialize(cts_buf);
  EXPECT_TRUE(itool_->Equal(cts, new_cts));
}

TEST_P(SerializeTest, ServerClientWorks) {
  // step 1. do serialize context
  auto buf_kit = kit_->Serialize();
  ASSERT_EQ(buf_kit.size(), kit_->Serialize(nullptr, 0));
  auto buf_pk = kit_->Serialize(HeKeyType::PublicKey);
  ASSERT_EQ(buf_pk.size(), kit_->Serialize(HeKeyType::PublicKey, nullptr, 0));
  auto buf_sk = kit_->Serialize(HeKeyType::SecretKey);
  ASSERT_EQ(buf_sk.size(), kit_->Serialize(HeKeyType::SecretKey, nullptr, 0));

  // step 2. client side: encrypt and send number to server
  auto edr = TryGetEncoder(kit_, "plain");
  std::vector<int64_t> pts_vec = {0, 1, -1, 2, -2, 3, 7, 8, 100, -1000, 1024};
  const auto pts = edr->Encode(pts_vec);
  std::vector<int64_t> cts_vec = {1024, -1024, 100, 13,   0,   1,
                                  -1,   2,     -1,  1000, -768};
  const auto cts = enc_->Encrypt(edr->Encode(cts_vec));

  auto pts_buf = kit_->GetItemTool()->Serialize(pts);
  ASSERT_EQ(pts_buf.size(), kit_->GetItemTool()->Serialize(pts, nullptr, 0));
  auto cts_buf = kit_->GetItemTool()->Serialize(cts);
  ASSERT_EQ(cts_buf.size(), kit_->GetItemTool()->Serialize(cts, nullptr, 0));

  // step 3. server side: deserialize and do add
  auto skit = HeFactory::Instance().Create(
      kit_->GetSchema(), ArgLib = kit_->GetLibraryName(),
      ArgParamsFrom = buf_kit, ArgPkFrom = buf_pk);
  // server has no sk, cannot decrypt
  EXPECT_FALSE(skit->HasSecretKey());
  EXPECT_ANY_THROW(skit->GetDecryptor());

  Item s_pts = skit->GetItemTool()->Deserialize(pts_buf);
  Item s_cts = skit->GetItemTool()->Deserialize(cts_buf);
  Item s_sum = skit->GetWordEvaluator()->Add(s_pts, s_cts);
  yacl::Buffer sum_buf(skit->GetItemTool()->Serialize(s_sum, nullptr, 0));
  skit->GetItemTool()->Serialize(s_sum, sum_buf.data<uint8_t>(),
                                 sum_buf.size());

  // step 4. client side: check the result
  // To simulate the scenario where the Client exits midway, we recreate the
  // HeKit on the Client side.
  std::shared_ptr<HeKit> ckit = HeFactory::Instance().Create(
      kit_->GetSchema(), ArgLib = kit_->GetLibraryName(),
      ArgParamsFrom = buf_kit, ArgPkFrom = buf_pk, ArgSkFrom = buf_sk);
  Item c_sum = ckit->GetItemTool()->Deserialize(sum_buf);
  c_sum = ckit->GetDecryptor()->Decrypt(c_sum);
  auto c_edr = TryGetEncoder(ckit, "plain");
  auto c_res = c_edr->DecodeInt64(c_sum);
  if (c_edr->SlotCount() > 1) {
    c_res.resize(pts_vec.size());
  }
  EXPECT_THAT(c_res, testing::ElementsAre(1024, -1023, 99, 15, -2, 4, 6, 10, 99,
                                          0, 256));
}

TEST_P(SerializeTest, SliceWorks) {
  auto edr = TryGetEncoder(kit_, "plain");

  std::vector<int64_t> pts_vec = {0, 1, -1, 2, -2, 3, 7, 8, 100, -1000, 1024};
  // test clone
  auto pts = itool_->Clone(edr->Encode(pts_vec));

  // todo: test append item and make the pts has same length

  // sub item
  ASSERT_EQ(itool_->ItemSize(pts),
            (11 + edr->SlotCount() - 1) / edr->SlotCount());

  if (itool_->ItemSize(pts) != 11) {
    GTEST_SKIP() << "encoder is not plain, skip test. info: " << *kit_;
  }

  auto sub_it = itool_->SubItem(pts, 5);
  EXPECT_THAT(edr->DecodeInt64(sub_it),
              testing::ElementsAre(3, 7, 8, 100, -1000, 1024));
  sub_it = itool_->SubItem(pts, 5, 2);
  EXPECT_THAT(edr->DecodeInt64(sub_it), testing::ElementsAre(3, 7));
  sub_it = itool_->SubItem(pts, 5, 1);
  EXPECT_THAT(edr->DecodeInt64(sub_it), testing::ElementsAre(3));

  // const mode
  const auto cts = itool_->Clone(kit_->GetEncryptor()->Encrypt(pts));
  const auto cts1 = itool_->SubItem(cts, 0);
  const auto cts2 = itool_->SubItem(cts1, 5, 100);
  EXPECT_THAT(edr->DecodeInt64(dec_->Decrypt(cts2)),
              testing::ElementsAre(3, 7, 8, 100, -1000, 1024));
  sub_it = itool_->SubItem(cts2, 0, 1);
  EXPECT_EQ(edr->DecodeScalarInt64(dec_->Decrypt(sub_it)), 3);
}

}  // namespace heu::spi::test
