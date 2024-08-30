// Copyright 2024 CyberChangAn Group, Xidian University.
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

#include "gtest/gtest.h"
#include "he_kit.h"

namespace heu::algos::ishe::test {
class iSHETest : public testing::Test {
 protected:
  std::unique_ptr<HeKit> hekit_;
  std::shared_ptr<SecretKey> secretkey_;
  std::shared_ptr<PublicParameters> publickey_;
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Decryptor> decryptor_;
  std::shared_ptr<Evaluator> evaluator_;
  std::shared_ptr<ItemTool> itemTool_ = std::make_shared<ItemTool>();

  void SetUp() override {
    hekit_ = HeKit::CreateParams(spi::Schema::iSHE, 4096, 160, 128);
    secretkey_ = hekit_->getSk();
    publickey_ = hekit_->getPk();
    encryptor_ = std::make_shared<Encryptor>(publickey_, secretkey_);
    decryptor_ = std::make_shared<Decryptor>(secretkey_, publickey_);
    evaluator_ = std::make_shared<Evaluator>(publickey_);
  }
};

TEST_F(iSHETest, ItomToolEvaluator) {
  uint8_t buff[1024], buff2[4096];
  Plaintext pt = Plaintext(1000);
  Ciphertext ct = encryptor_->Encrypt(pt);
  auto pt_serialization = itemTool_->Serialize(pt, buff, size_t(1024));
  auto ct_serialization = itemTool_->Serialize(ct, buff2, size_t(4096));
  Plaintext p1;
  yacl::ByteContainerView bc1 = yacl::ByteContainerView(buff, pt_serialization);
  p1 = itemTool_->DeserializePT(bc1);
  Ciphertext c1;
  yacl::ByteContainerView bc2 =
      yacl::ByteContainerView(buff2, ct_serialization);
  c1 = itemTool_->DeserializeCT(bc2);
  EXPECT_EQ(p1, pt);
  EXPECT_EQ(c1.n_, ct.n_);
  EXPECT_EQ(c1.d_, ct.d_);

  Plaintext pt1 = itemTool_->Clone(pt);
  EXPECT_EQ(pt, pt1);
  Ciphertext ct2 = itemTool_->Clone(ct);
  EXPECT_EQ(ct, ct2);
}

TEST_F(iSHETest, OperationEvaluate) {
  Plaintext m0 = Plaintext(12345);
  Plaintext m1 = Plaintext(-20000);
  Plaintext m3 = Plaintext(0);
  Ciphertext c0 = encryptor_->Encrypt(m0);
  Ciphertext c1 = encryptor_->Encrypt(m1);
  Ciphertext c2 = encryptor_->Encrypt(-m0);
  Ciphertext c3 = encryptor_->Encrypt(m3);
  EXPECT_EQ(m0, Plaintext(12345));

  Plaintext plain;
  Ciphertext res;

  // evaluate add
  res = evaluator_->Add(c0, c0);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 * 2));
  res = evaluator_->Add(c1, c1);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-20000 * 2));
  res = evaluator_->Add(c0, c1);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 - 20000));
  res = evaluator_->Add(c1, m3);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-20000));
  res = evaluator_->Add(c0, m1);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 - 20000));
  res = evaluator_->Add(c1, m0);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 - 20000));
  res = evaluator_->Add(c2, c0);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(0));

  Plaintext m2 = Plaintext(123);
  Ciphertext c4 = encryptor_->Encrypt(m2);
  Ciphertext c5 = encryptor_->Encrypt(-m2);
  res = evaluator_->Mul(c0, c0);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 * 12345));
  res = evaluator_->Mul(c1, c1);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(20000 * 20000));
  res = evaluator_->Mul(c0, m0);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(12345 * 12345));
  res = evaluator_->Mul(c4, c4);
  res = evaluator_->Mul(res, c4);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(123 * 123 * 123));
  res = evaluator_->Mul(c1, m0);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(-20000 * 12345));
  res = evaluator_->Mul(c1, m1);
  decryptor_->Decrypt(res, &plain);
  EXPECT_EQ(plain, Plaintext(20000 * 20000));

  Ciphertext Zero = encryptor_->EncryptZeroT();
  decryptor_->Decrypt(Zero, &plain);
  EXPECT_EQ(plain, MPInt(0));
  evaluator_->Randomize(&c1);
  decryptor_->Decrypt(c1, &plain);
  EXPECT_EQ(plain, MPInt(-20000));

  evaluator_->MulInplace(&c0, m1);
  decryptor_->Decrypt(c0, &plain);
  EXPECT_EQ(plain, MPInt(-20000 * 12345));

  evaluator_->MulInplace(&c1, c1);
  decryptor_->Decrypt(c1, &plain);
  EXPECT_EQ(plain, MPInt(20000 * 20000));

  Plaintext pt0 = Plaintext(12345);
  Plaintext pt1 = Plaintext(20000);
  Ciphertext ct0 = encryptor_->Encrypt(pt0);
  Ciphertext ct1 = encryptor_->Encrypt(pt1);
  evaluator_->AddInplace(&ct0, pt1);  // call add, test Inplace function
  decryptor_->Decrypt(ct0, &plain);
  EXPECT_EQ(plain, MPInt(20000 + 12345));
  evaluator_->AddInplace(&ct0, ct1);
  decryptor_->Decrypt(ct0, &plain);
  EXPECT_EQ(plain, MPInt(20000 + 12345 + 20000));
}

TEST_F(iSHETest, NegateEvalutate) {
  Plaintext p1 = Plaintext(123456);
  evaluator_->NegateInplace(&p1);
  EXPECT_EQ(p1, MPInt(-123456));  // p1 = -123456
  Plaintext p2 = Plaintext(123456);
  p2 = evaluator_->Negate(p2);
  EXPECT_EQ(p2, MPInt(-123456));  // p2 = -123456

  Plaintext plain;
  evaluator_->NegateInplace(&p1);  //  p1 = -123456
  Ciphertext c1 = encryptor_->Encrypt(p2);
  evaluator_->NegateInplace(&c1);
  decryptor_->Decrypt(c1, &plain);
  EXPECT_EQ(plain, MPInt(123456));
}

TEST_F(iSHETest, PlaintextEvaluate) {
  Plaintext p1 = Plaintext(2000);
  Plaintext p2 = evaluator_->Square(p1);
  evaluator_->SquareInplace(&p1);
  EXPECT_EQ(p1, MPInt(2000 * 2000));
  EXPECT_EQ(p1, p2);

  Plaintext p3 = Plaintext(200);
  Plaintext p4 = evaluator_->Pow(p3, 5);
  evaluator_->PowInplace(&p3, 5);
  EXPECT_EQ(p3, p4);
}
}  // namespace heu::algos::ishe::test