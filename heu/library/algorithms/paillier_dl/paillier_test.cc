// Copyright 2023 Denglin Co., Ltd.
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

#include "heu/library/algorithms/paillier_dl/paillier.h"
#include <string>
#include "gtest/gtest.h"
#include "heu/library/algorithms/paillier_dl/utils.h"

namespace heu::lib::algorithms::paillier_dl::test {

class DLPaillierTest : public ::testing::Test {
 protected:
  void SetUp() override {
    KeyGenerator::Generate(256, &sk_, &pk_);
    evaluator_ = std::make_shared<Evaluator>(pk_);
    decryptor_ = std::make_shared<Decryptor>(pk_, sk_);
    encryptor_ = std::make_shared<Encryptor>(pk_);
  }

 protected:
  SecretKey sk_;
  PublicKey pk_;
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Evaluator> evaluator_;
  std::shared_ptr<Decryptor> decryptor_;
};

TEST_F(DLPaillierTest, VectorEncryptDecrypt) {
  std::vector<MPInt> pts_vec ={Plaintext(-12345), Plaintext(12345)};
  std::vector<MPInt> gpts_vec ={Plaintext(-12345), Plaintext(12345)};

  std::vector<MPInt *> pts_pt;
  ValueVecToPtsVec(pts_vec, pts_pt);
  auto pts_span = absl::MakeConstSpan(pts_pt.data(), pts_vec.size());
  auto cts_vec = encryptor_->Encrypt(pts_span);
  std::vector<Ciphertext *> cts_pt;
  ValueVecToPtsVec(cts_vec, cts_pt);
  auto cts_span = absl::MakeConstSpan(cts_pt.data(), cts_vec.size());
  auto depts_vec = decryptor_->Decrypt(cts_span);

  for (int i=0; i<gpts_vec.size(); i++) {
      EXPECT_EQ(gpts_vec[i], depts_vec[i]);
  }
}

TEST_F(DLPaillierTest, VectorvaluateCiphertextAddCiphertext) {
  std::vector<MPInt> pts_vec ={Plaintext(-12345), Plaintext(23456)};
  std::vector<MPInt> gpts_vec ={Plaintext(-12345*2), Plaintext(23456*2)};

  std::vector<MPInt *> pts_pt;
  ValueVecToPtsVec(pts_vec, pts_pt);
  auto pts_span = absl::MakeConstSpan(pts_pt.data(), pts_vec.size());
  auto cts_vec = encryptor_->Encrypt(pts_span);
  std::vector<Ciphertext *> cts_pt;
  ValueVecToPtsVec(cts_vec, cts_pt);
  auto cts_span = absl::MakeConstSpan(cts_pt.data(), cts_vec.size());

  auto res0_vec = evaluator_->Add(cts_span, cts_span);
  std::vector<Ciphertext *> res0_pt;
  ValueVecToPtsVec(res0_vec, res0_pt);
  auto res0_span = absl::MakeConstSpan(res0_pt.data(), res0_vec.size());

  auto depts0_vec = decryptor_->Decrypt(res0_span);

  for (int i=0; i<gpts_vec.size(); i++) {
      EXPECT_EQ(gpts_vec[i], depts0_vec[i]);
  }
}

TEST_F(DLPaillierTest, VectorEvaluateCiphertextSubCiphertext) {
  std::vector<MPInt> pts0_vec ={Plaintext(12345), Plaintext(23456)};
  std::vector<MPInt> pts1_vec ={Plaintext(23456), Plaintext(12345)};
  std::vector<MPInt> gpts_vec ={Plaintext(12345-23456), Plaintext(23456-12345)};
  
  std::vector<MPInt *> pts0_pt;
  ValueVecToPtsVec(pts0_vec, pts0_pt);
  auto pts0_span = absl::MakeConstSpan(pts0_pt.data(), pts0_vec.size());
  auto cts0_vec = encryptor_->Encrypt(pts0_span);
  std::vector<Ciphertext *> cts0_pt;
  ValueVecToPtsVec(cts0_vec, cts0_pt);
  auto cts0_span = absl::MakeConstSpan(cts0_pt.data(), cts0_vec.size());

  std::vector<MPInt *> pts1_pt;
  ValueVecToPtsVec(pts1_vec, pts1_pt);
  auto pts1_span = absl::MakeConstSpan(pts1_pt.data(), pts1_vec.size());
  auto cts1_vec = encryptor_->Encrypt(pts1_span);
  std::vector<Ciphertext *> cts1_pt;
  ValueVecToPtsVec(cts1_vec, cts1_pt);
  auto cts1_span = absl::MakeConstSpan(cts1_pt.data(), cts1_vec.size());

  auto res0_vec = evaluator_->Sub(cts0_span, cts1_span);
  std::vector<Ciphertext *> res0_pt;
  ValueVecToPtsVec(res0_vec, res0_pt);
  auto res0_span = absl::MakeConstSpan(res0_pt.data(), res0_vec.size());
  
  auto depts0_vec = decryptor_->Decrypt(res0_span);

  for (int i=0; i<gpts_vec.size(); i++) {
      EXPECT_EQ(gpts_vec[i], depts0_vec[i]);
  }
}

TEST_F(DLPaillierTest, VectorEvaluateCiphertextAddPlaintext) {
  std::vector<MPInt> pts_vec ={Plaintext(12345), Plaintext(-23456)};
  std::vector<MPInt> gpts_vec ={Plaintext(12345*2), Plaintext(-23456*2)};

  std::vector<MPInt *> pts_pt;
  ValueVecToPtsVec(pts_vec, pts_pt);
  auto pts_span = absl::MakeConstSpan(pts_pt.data(), pts_vec.size());
  auto cts_vec = encryptor_->Encrypt(pts_span);
  std::vector<Ciphertext *> cts_pt;
  ValueVecToPtsVec(cts_vec, cts_pt);
  auto cts_span = absl::MakeConstSpan(cts_pt.data(), cts_vec.size());

  auto res0_vec = evaluator_->Add(cts_span, pts_span);
  std::vector<Ciphertext *> res0_pt;
  ValueVecToPtsVec(res0_vec, res0_pt);
  auto res0_span = absl::MakeConstSpan(res0_pt.data(), res0_vec.size());

  auto depts0_vec = decryptor_->Decrypt(res0_span);

  for (int i=0; i<gpts_vec.size(); i++) {
      EXPECT_EQ(gpts_vec[i], depts0_vec[i]);
  }
}

TEST_F(DLPaillierTest, VectorEvaluateCiphertextSubPlaintext) {
  std::vector<MPInt> pts0_vec ={Plaintext(12345), Plaintext(23456)};
  std::vector<MPInt> pts1_vec ={Plaintext(23456), Plaintext(12345)};
  std::vector<MPInt> gpts_vec ={Plaintext(12345-23456), Plaintext(23456-12345)};

  std::vector<MPInt *> pts0_pt;
  ValueVecToPtsVec(pts0_vec, pts0_pt);
  auto pts0_span = absl::MakeConstSpan(pts0_pt.data(), pts0_vec.size());
  auto cts0_vec = encryptor_->Encrypt(pts0_span);
  std::vector<Ciphertext *> cts0_pt;
  ValueVecToPtsVec(cts0_vec, cts0_pt);
  auto cts0_span = absl::MakeConstSpan(cts0_pt.data(), cts0_vec.size());

  std::vector<MPInt *> pts1_pt;
  ValueVecToPtsVec(pts1_vec, pts1_pt);
  auto pts1_span = absl::MakeConstSpan(pts1_pt.data(), pts1_vec.size());
  auto res0_vec = evaluator_->Sub(cts0_span, pts1_span);
  std::vector<Ciphertext *> res0_pt;
  ValueVecToPtsVec(res0_vec, res0_pt);
  auto res0_span = absl::MakeConstSpan(res0_pt.data(), res0_vec.size());

  auto depts0_vec = decryptor_->Decrypt(res0_span);

  for (int i=0; i<gpts_vec.size(); i++) {
      EXPECT_EQ(gpts_vec[i], depts0_vec[i]);
  }
}

TEST_F(DLPaillierTest, VectorEvaluateCiphertextMulPlaintext) {
  std::vector<MPInt> pts_vec ={Plaintext(12345), Plaintext(23456)};
  std::vector<MPInt> gpts_vec ={Plaintext(12345*12345), Plaintext(23456*23456)};

  std::vector<MPInt *> pts_pt;
  ValueVecToPtsVec(pts_vec, pts_pt);
  auto pts_span = absl::MakeConstSpan(pts_pt.data(), pts_vec.size());
  auto cts_vec = encryptor_->Encrypt(pts_span);
  std::vector<Ciphertext *> cts_pt;
  ValueVecToPtsVec(cts_vec, cts_pt);
  auto cts_span = absl::MakeConstSpan(cts_pt.data(), cts_vec.size());

  auto res0_vec = evaluator_->Mul(cts_span, pts_span);
  std::vector<Ciphertext *> res0_pt;
  ValueVecToPtsVec(res0_vec, res0_pt);
  auto res0_span = absl::MakeConstSpan(res0_pt.data(), res0_vec.size());

  auto depts0_vec = decryptor_->Decrypt(res0_span);

  for (int i=0; i<gpts_vec.size(); i++) {
      EXPECT_EQ(gpts_vec[i], depts0_vec[i]);
  }
}

TEST_F(DLPaillierTest, VectorEvaluateCiphertextNeg) { 
  std::vector<MPInt> pts_vec ={Plaintext(12345), Plaintext(23456)};
  std::vector<MPInt> gpts_vec ={Plaintext(-12345), Plaintext(-23456)};

  std::vector<MPInt *> pts_pt;
  ValueVecToPtsVec(pts_vec, pts_pt);
  auto pts_span = absl::MakeConstSpan(pts_pt.data(), pts_vec.size());
  auto cts_vec = encryptor_->Encrypt(pts_span);
  std::vector<Ciphertext *> cts_pt;
  ValueVecToPtsVec(cts_vec, cts_pt);
  auto cts_span = absl::MakeConstSpan(cts_pt.data(), cts_vec.size());

  auto res0_vec = evaluator_->Negate(cts_span);
  std::vector<Ciphertext *> res0_pt;
  ValueVecToPtsVec(res0_vec, res0_pt);
  auto res0_span = absl::MakeConstSpan(res0_pt.data(), res0_vec.size());

  auto depts0_vec = decryptor_->Decrypt(res0_span);

  for (int i=0; i<gpts_vec.size(); i++) {
      EXPECT_EQ(gpts_vec[i], depts0_vec[i]);
  }
}

}  // namespace heu::lib::algorithms::paillier_dl::test


int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}