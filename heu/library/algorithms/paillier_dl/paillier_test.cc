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

namespace heu::lib::algorithms::paillier_dl::test {

class ZPaillierTest : public ::testing::Test {
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

TEST_F(ZPaillierTest, VectorEncryptDecrypt) {
  std::vector<MPInt> pts ={Plaintext(-12345), Plaintext(12345)};
  std::vector<MPInt> gpts ={Plaintext(-12345), Plaintext(12345)};
  std::vector<Ciphertext> cts = encryptor_->Encrypt(pts);

  std::vector<Plaintext> depts;
  for (int i=0; i<cts.size(); i++) {
    Plaintext pt;
    depts.push_back(pt);
  }
  decryptor_->Decrypt(cts, depts);

  for (int i=0; i<gpts.size(); i++) {
      EXPECT_EQ(gpts[i], depts[i]);
  }
}

TEST_F(ZPaillierTest, VectorvaluateCiphertextAddCiphertext) {
  std::vector<MPInt> pts ={Plaintext(-12345), Plaintext(23456)};
  std::vector<MPInt> gpts ={Plaintext(-12345*2), Plaintext(23456*2)};
  std::vector<Ciphertext> cts = encryptor_->Encrypt(pts);

  std::vector<Ciphertext> res0;
  res0 = evaluator_->Add(cts, cts);

  std::vector<Plaintext> depts0;
  for (int i=0; i<res0.size(); i++) {
    Plaintext pt;
    depts0.push_back(pt);
  }
  decryptor_->Decrypt(res0, depts0);

  for (int i=0; i<gpts.size(); i++) {
      EXPECT_EQ(gpts[i], depts0[i]);
  }
}

TEST_F(ZPaillierTest, VectorEvaluateCiphertextSubCiphertext) {
  std::vector<MPInt> pts0 ={Plaintext(12345), Plaintext(23456)};
  std::vector<MPInt> pts1 ={Plaintext(23456), Plaintext(12345)};
  std::vector<MPInt> gpts ={Plaintext(12345-23456), Plaintext(23456-12345)};
  std::vector<Ciphertext> cts0 = encryptor_->Encrypt(pts0);
  std::vector<Ciphertext> cts1 = encryptor_->Encrypt(pts1);

  std::vector<Ciphertext> res0;
  res0 = evaluator_->Sub(cts0, cts1);

  std::vector<Plaintext> depts0;
  for (int i=0; i<res0.size(); i++) {
    Plaintext pt;
    depts0.push_back(pt);
  }
  decryptor_->Decrypt(res0, depts0);

  for (int i=0; i<gpts.size(); i++) {
      EXPECT_EQ(gpts[i], depts0[i]);
  }
}

TEST_F(ZPaillierTest, VectorEvaluateCiphertextAddPlaintext) {
  std::vector<MPInt> pts ={Plaintext(12345), Plaintext(-23456)};
  std::vector<MPInt> gpts ={Plaintext(12345*2), Plaintext(-23456*2)};

  std::vector<Ciphertext> cts = encryptor_->Encrypt(pts);

  std::vector<Ciphertext> res0;
  res0 = evaluator_->Add(cts, pts);

  std::vector<Plaintext> depts0;
  for (int i=0; i<res0.size(); i++) {
    Plaintext pt;
    depts0.push_back(pt);
  }
  decryptor_->Decrypt(res0, depts0);

  for (int i=0; i<gpts.size(); i++) {
      EXPECT_EQ(gpts[i], depts0[i]);
  }
}

TEST_F(ZPaillierTest, VectorEvaluateCiphertextSubPlaintext) {
  std::vector<MPInt> pts0 ={Plaintext(12345), Plaintext(23456)};
  std::vector<MPInt> pts1 ={Plaintext(23456), Plaintext(12345)};
  std::vector<MPInt> gpts ={Plaintext(12345-23456), Plaintext(23456-12345)};
  std::vector<Ciphertext> cts0 = encryptor_->Encrypt(pts0);

  std::vector<Ciphertext> res0;
  res0 = evaluator_->Sub(cts0, pts1);

  std::vector<Plaintext> depts0;
  for (int i=0; i<res0.size(); i++) {
    Plaintext pt;
    depts0.push_back(pt);
  }
  decryptor_->Decrypt(res0, depts0);

  for (int i=0; i<gpts.size(); i++) {
      EXPECT_EQ(gpts[i], depts0[i]);
  }
}

TEST_F(ZPaillierTest, VectorEvaluateCiphertextMulPlaintext) {
  std::vector<MPInt> pts ={Plaintext(12345), Plaintext(23456)};
  std::vector<MPInt> gpts ={Plaintext(12345*12345), Plaintext(23456*23456)};

  std::vector<Ciphertext> cts = encryptor_->Encrypt(pts);

  std::vector<Ciphertext> res0;
  res0 = evaluator_->Mul(cts, pts);

  std::vector<Plaintext> depts0;
  for (int i=0; i<res0.size(); i++) {
    Plaintext pt;
    depts0.push_back(pt);
  }
  decryptor_->Decrypt(res0, depts0);

  for (int i=0; i<gpts.size(); i++) {
      EXPECT_EQ(gpts[i], depts0[i]);
  }
}

TEST_F(ZPaillierTest, VectorEvaluateCiphertextNeg) { 
  std::vector<MPInt> pts ={Plaintext(12345), Plaintext(23456)};
  std::vector<MPInt> gpts ={Plaintext(-12345), Plaintext(-23456)};

  std::vector<Ciphertext> cts = encryptor_->Encrypt(pts);

  std::vector<Ciphertext> res0;
  res0 = evaluator_->Negate(cts);

  std::vector<Plaintext> depts0;
  for (int i=0; i<res0.size(); i++) {
    Plaintext pt;
    depts0.push_back(pt);
  }
  decryptor_->Decrypt(res0, depts0);

  for (int i=0; i<gpts.size(); i++) {
      EXPECT_EQ(gpts[i], depts0[i]);
  }
}
}  // namespace heu::lib::algorithms::paillier_dl::test


int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
