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

#include "heu/algorithms/incubator/ishe/he_kit.h"

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

TEST_F(iSHETest, serializeEvaluate) {
  // Serialize publicparam
  yacl::Buffer pk_buf = publickey_->Serialize2Buffer();
  // Serialize secretKey
  yacl::Buffer sk_buf = secretkey_->Serialize2Buffer();
  // operation ct
  Ciphertext ct_pos = encryptor_->Encrypt(MPInt(100000));
  Ciphertext ct_zero = encryptor_->Encrypt(MPInt(0));
  Ciphertext ct_neg = encryptor_->Encrypt(MPInt(-123456));
  yacl::Buffer pos_buffer = ct_pos.Serialize();
  yacl::Buffer zero_buffer = ct_zero.Serialize();
  yacl::Buffer neg_buffer = ct_neg.Serialize();
  // Deserialize and compare
  std::shared_ptr<PublicParameters> pp = PublicParameters::LoadFrom(pk_buf);
  EXPECT_EQ(pp->getN(), publickey_->getN());
  EXPECT_EQ(pp->k_0, publickey_->k_0);
  EXPECT_EQ(pp->k_r, publickey_->k_r);
  EXPECT_EQ(pp->k_M, publickey_->k_M);
  EXPECT_EQ(pp->ONES, publickey_->ONES);
  EXPECT_EQ(pp->ADDONES, publickey_->ADDONES);
  EXPECT_EQ(pp->NEGS, publickey_->NEGS);
  // deserialze cts
  Ciphertext pos_from_buf, zero_from_buf, neg_from_buf;
  pos_from_buf.Deserialize(pos_buffer);
  zero_from_buf.Deserialize(zero_buffer);
  neg_from_buf.Deserialize(neg_buffer);
  // operations
  Ciphertext o1, o2, o3, o4, o5;
  o1 = evaluator_->Add(pos_from_buf, zero_from_buf);
  o2 = evaluator_->Add(neg_from_buf, zero_from_buf);
  o3 = evaluator_->Add(pos_from_buf, neg_from_buf);
  o4 = evaluator_->Mul(pos_from_buf, zero_from_buf);
  o5 = evaluator_->Mul(pos_from_buf, neg_from_buf);
  // Serialize results
  yacl::Buffer bo1 = o1.Serialize();
  yacl::Buffer bo2 = o2.Serialize();
  yacl::Buffer bo3 = o3.Serialize();
  yacl::Buffer bo4 = o4.Serialize();
  yacl::Buffer bo5 = o5.Serialize();
  // Deserialize sk
  std::shared_ptr<SecretKey> sk = SecretKey::LoadFrom(sk_buf);
  EXPECT_EQ(sk->getS(), secretkey_->getS());
  EXPECT_EQ(sk->getP(), secretkey_->getP());
  EXPECT_EQ(sk->getL(), secretkey_->getL());
  // Deserialize results
  o1.Deserialize(bo1);
  o2.Deserialize(bo2);
  o3.Deserialize(bo3);
  o4.Deserialize(bo4);
  o5.Deserialize(bo5);
  EXPECT_EQ(decryptor_->Decrypt(o1), MPInt(100000));
  EXPECT_EQ(decryptor_->Decrypt(o2), MPInt(-123456));
  EXPECT_EQ(decryptor_->Decrypt(o3), MPInt(-23456));
  EXPECT_EQ(decryptor_->Decrypt(o4), MPInt(0));
  EXPECT_EQ(decryptor_->Decrypt(o5), MPInt(-123456) * MPInt(100000));
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
  // m < pp_->MessageSpace()[1] && m >= pp_->MessageSpace()[0]
  Plaintext pt_min = Plaintext(publickey_->MessageSpace()[0]);
  Plaintext pt_max = Plaintext(publickey_->MessageSpace()[1] - 1_mp);
  Ciphertext ct_max = encryptor_->Encrypt(pt_max);
  Ciphertext ct_min = encryptor_->Encrypt(pt_min);
  Plaintext tmp = decryptor_->Decrypt(ct_min);
  EXPECT_EQ(tmp, pt_min);
  tmp = decryptor_->Decrypt(ct_max);
  EXPECT_EQ(tmp, pt_max);
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
