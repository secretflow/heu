// Copyright 2023 Ant Group Co., Ltd.
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

#include <string>

#include "gtest/gtest.h"

#include "heu/library/algorithms/paillier_gpu/paillier.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_g::test {

template <typename T>
using Span = absl::Span<T *const>;

template <typename T>
using ConstSpan = absl::Span<const T *const>;

class GPUTest : public ::testing::Test {
 protected:
  void SetUp() override {
    KeyGenerator::Generate(2048, &sk_, &pk_);
    encryptor_ = std::make_shared<Encryptor>(pk_);
    decryptor_ = std::make_shared<Decryptor>(pk_, sk_);
    evaluator_ = std::make_shared<Evaluator>(pk_);
  }

  void EncDec(int128_t a, int128_t b, int128_t c, int128_t d);
  void CiphertextsRandomize(int128_t a, int128_t b);

  void CiphertextsAdd(int128_t a, int128_t b, int128_t c);
  void CiphertextsAddInplace(int128_t a, int128_t b, int128_t c);
  void PlaintextsAdd(int128_t a, int128_t b, int128_t c, int128_t d, int128_t e,
                     int128_t f);
  void PlaintextsAddInplace(int128_t a, int128_t b, int128_t c, int128_t d,
                            int128_t e, int128_t f);
  void CiphertextsAddPlaintexts(int128_t a, int128_t b, int128_t c);
  void PlaintextsAddCiphertexts(int128_t a, int128_t b, int128_t c);
  void PlaintextsAddCiphertextsInplace(int128_t a, int128_t b, int128_t c);

  void CtsMulPts(int128_t a, int128_t b, int128_t c);
  void PtsMulCts(int128_t a, int128_t b, int128_t c);
  void PtsMulPts(int128_t a, int128_t b, int128_t c, int128_t d, int128_t e,
                 int128_t f);
  void CtsMulPtsInplace(int128_t a, int128_t b, int128_t c);
  void PtsMulPtsInplace(int128_t a, int128_t b, int128_t c, int128_t d,
                        int128_t e, int128_t f);

  void CiphertextsNegate(int128_t a, int128_t b);
  void CiphertextsNegateInplace(int128_t a, int128_t b);

  void CiphertextsSub(int128_t a, int128_t b, int128_t c);
  void CtsSubPts(int128_t a, int128_t b, int128_t c);
  void PtsSubCts(int128_t a, int128_t b, int128_t c);
  void PtsSubPts(int128_t a, int128_t b, int128_t c);
  void CiphertextsSubInplace(int128_t a, int128_t b, int128_t c);
  void CtsSubPtsInplace(int128_t a, int128_t b, int128_t c);
  void PtsSubPtsInplace(int128_t a, int128_t b, int128_t c);

 protected:
  SecretKey sk_;
  PublicKey pk_;
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Evaluator> evaluator_;
  std::shared_ptr<Decryptor> decryptor_;
  // [-9223372036854775808, 9223372036854775807]
  static const int128_t iLow = std::numeric_limits<int64_t>::lowest();
  static const int128_t iMax = std::numeric_limits<int64_t>::max();
};

// int64 range: [-9223372036854775808, 9223372036854775807]

void GPUTest::EncDec(int128_t a, int128_t b, int128_t c, int128_t d) {
  Plaintext p[2]{Plaintext(a), Plaintext(b)};
  Plaintext *ppts[2];
  ppts[0] = &p[0];
  ppts[1] = &p[1];
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> pts = absl::MakeConstSpan(ppts, 2);

  std::vector<Ciphertext> res = encryptor_->Encrypt(pts);

  // // EncryptWithAudit
  // auto auditRes = encryptor_->EncryptWithAudit(pts);
  // std::vector<Ciphertext> resVec = auditRes.first;
  // std::vector<std::string> strVec = auditRes.second;
  // for (unsigned int i = 0; i < strVec.size(); i++) {
  //   printf("EncryptWithAudit : %d  %s\n", i, strVec[i].c_str());
  // }

  // make the constspan for vector Decrypt
  ConstSpan<Ciphertext> cts;
  Ciphertext *ccts[2];
  ccts[0] = &res[0];
  ccts[1] = &res[1];
  // create the constspan for GPU call
  cts = absl::MakeConstSpan(ccts, 2);
  // receive the GPU Decrypt results
  std::vector<Plaintext> apts;
  apts = decryptor_->Decrypt(cts);

  EXPECT_EQ(apts[0], Plaintext(c));
  EXPECT_EQ(apts[1], Plaintext(d));
}

TEST_F(GPUTest, EncDecTest) {
  EncDec(1, 2, 1, 2);
  EncDec(-1, 0, -1, 0);
  EncDec(-3, std::numeric_limits<int64_t>::max(), -3,
         std::numeric_limits<int64_t>::max());
  EncDec(-65530, -123, -65530, -123);
  EncDec(std::numeric_limits<int64_t>::lowest(), 0,
         std::numeric_limits<int64_t>::lowest(), 0);
}

void GPUTest::CiphertextsAdd(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1, res2;  // receive the GPU Encrypt results
  res1 = encryptor_->Encrypt(cts1);
  res2 = encryptor_->Encrypt(cts2);

  Ciphertext *cct1[1];
  Ciphertext *cct2[1];
  cct1[0] = &res1[0];
  cct2[0] = &res2[0];
  ConstSpan<Ciphertext> ct0 = absl::MakeConstSpan(cct1, 1);
  ConstSpan<Ciphertext> ct1 = absl::MakeConstSpan(cct2, 1);
  std::vector<Ciphertext> sum = evaluator_->Add(ct0, ct1);

  // make the constspan for vector Decrypt
  Ciphertext *ccts[1]{&sum[0]};
  ConstSpan<Ciphertext> cts = absl::MakeConstSpan(ccts, 1);
  std::vector<Plaintext> apts;
  apts = decryptor_->Decrypt(cts);

  EXPECT_EQ(apts[0], Plaintext(c));
}

TEST_F(GPUTest, CiphertextsAddTest) {
  CiphertextsAdd(-2, -4, -6);
  CiphertextsAdd(123, 234, 357);
  CiphertextsAdd(-123, 234, 111);
  CiphertextsAdd(234, -123, 111);
  CiphertextsAdd(iLow, iMax, -1);
  CiphertextsAdd(iLow, iLow, iLow * 2);
  CiphertextsAdd(iMax, iMax, iMax * 2);
}

void GPUTest::CiphertextsAddInplace(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1, res2;  // receive the GPU Encrypt results
  res1 = encryptor_->Encrypt(cts1);
  res2 = encryptor_->Encrypt(cts2);

  Ciphertext *cct1[1];
  Ciphertext *cct2[1];
  cct1[0] = &res1[0];
  cct2[0] = &res2[0];
  Span<Ciphertext> ct0 = absl::MakeSpan(cct1, 1);
  ConstSpan<Ciphertext> ct1 = absl::MakeConstSpan(cct2, 1);
  evaluator_->AddInplace(ct0, ct1);

  std::vector<Plaintext> apts = decryptor_->Decrypt(ct0);
  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, CiphertextsAddInplaceTest) {
  CiphertextsAddInplace(5, 2, 7);
  CiphertextsAddInplace(5, -7, -2);
  CiphertextsAddInplace(-5, 7, 2);
  CiphertextsAddInplace(-5, -7, -12);
}

void GPUTest::CiphertextsRandomize(int128_t a, int128_t b) {
  Plaintext p1(a);
  Plaintext *ppts1[1]{&p1};
  ConstSpan<Plaintext> cts = absl::MakeConstSpan(ppts1, 1);

  std::vector<Ciphertext> res = encryptor_->Encrypt(cts);
  std::vector<Ciphertext> res2{res[0]};

  Ciphertext *cct1[1]{&res[0]};
  Span<Ciphertext> ct0 = absl::MakeSpan(cct1, 1);
  evaluator_->Randomize(ct0);

  std::vector<Plaintext> apts = decryptor_->Decrypt(ct0);

  EXPECT_EQ(apts[0], b);
  EXPECT_NE(res2[0], *ct0[0]);
}

TEST_F(GPUTest, CiphertextsRandomize) {
  CiphertextsRandomize(5, 5);
  CiphertextsRandomize(0, 0);
  CiphertextsRandomize(-123, -123);
  CiphertextsRandomize(iLow, iLow);
  CiphertextsRandomize(iMax, iMax);
}

// PlaintextsAdd
void GPUTest::PlaintextsAdd(int128_t a, int128_t b, int128_t c, int128_t d,
                            int128_t e, int128_t f) {
  Plaintext p11(a);
  Plaintext p12(b);
  Plaintext p21(c);
  Plaintext p22(d);

  Plaintext *ppts1[2]{&p11, &p12};
  Plaintext *ppts2[2]{&p21, &p22};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> pts1 = absl::MakeConstSpan(ppts1, 2);
  ConstSpan<Plaintext> pts2 = absl::MakeConstSpan(ppts2, 2);

  std::vector<Plaintext> res = evaluator_->Add(pts1, pts2);

  EXPECT_EQ(res[0], e);
  EXPECT_EQ(res[1], f);
}

TEST_F(GPUTest, PlaintextsAddTest) {
  PlaintextsAdd(-5, 7, 8, -9, 3, -2);
  PlaintextsAdd(3, 7, 8, 9, 11, 16);
  PlaintextsAdd(-3, -7, -8, -9, -11, -16);
}

// PlaintextsAddInplace
void GPUTest::PlaintextsAddInplace(int128_t a, int128_t b, int128_t c,
                                   int128_t d, int128_t e, int128_t f) {
  Plaintext p11(a);
  Plaintext p12(b);
  Plaintext p21(c);
  Plaintext p22(d);
  Plaintext *ppts1[2]{&p11, &p12};
  Plaintext *ppts2[2]{&p21, &p22};
  // make the constspan for vector Encrypt
  Span<Plaintext> pts1 = absl::MakeSpan(ppts1, 2);
  ConstSpan<Plaintext> pts2 = absl::MakeConstSpan(ppts2, 2);

  evaluator_->AddInplace(pts1, pts2);

  std::cout << "PlaintextsAddInplace " << *pts1[0] << " -- " << *pts1[1]
            << " -- " << *pts2[0] << " -- " << *pts2[1] << std::endl;
  EXPECT_EQ(*pts1[0], e);
  EXPECT_EQ(*pts1[1], f);
}

TEST_F(GPUTest, PlaintextsAddInplace) {
  PlaintextsAdd(-5, 7, 8, -9, 3, -2);
  PlaintextsAdd(3, 7, 8, 9, 11, 16);
  PlaintextsAdd(-3, -7, -8, -9, -11, -16);
}

// dec(ct1 + pt2) = pt1 + pt2
void GPUTest::CiphertextsAddPlaintexts(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1;  // receive the GPU Encrypt results
  res1 = encryptor_->Encrypt(cts1);

  Ciphertext *cct1[1];
  cct1[0] = &res1[0];
  ConstSpan<Ciphertext> ct0 = absl::MakeConstSpan(cct1, 1);
  std::vector<Ciphertext> sum = evaluator_->Add(ct0, cts2);
  // make the constspan for vector Decrypt
  Ciphertext *ccts[1]{&sum[0]};
  ConstSpan<Ciphertext> cts =
      absl::MakeConstSpan(ccts, 1);  // create the constspan for GPU call
  std::vector<Plaintext> apts = decryptor_->Decrypt(cts);

  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, CiphertextsAddPlaintexts) {
  CiphertextsAddPlaintexts(123, 2, 125);
  CiphertextsAddPlaintexts(123, -2, 121);
  CiphertextsAddPlaintexts(-123, 2, -121);
  CiphertextsAddPlaintexts(-123, -2, -125);
  CiphertextsAddPlaintexts(iLow, iMax, -1);
}

// dec(pt2 + ct1) = pt1 + pt2
void GPUTest::PlaintextsAddCiphertexts(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 1);
  std::vector<Ciphertext> res1;  // receive the GPU Encrypt results
  res1 = encryptor_->Encrypt(cts1);

  Ciphertext *cct1[1];
  cct1[0] = &res1[0];
  ConstSpan<Ciphertext> ct0 = absl::MakeConstSpan(cct1, 1);
  std::vector<Ciphertext> sum = evaluator_->Add(cts2, ct0);

  // make the constspan for vector Decrypt
  Ciphertext *ccts[1]{&sum[0]};
  ConstSpan<Ciphertext> cts =
      absl::MakeConstSpan(ccts, 1);  // create the constspan for GPU call
  std::vector<Plaintext> apts = decryptor_->Decrypt(cts);
  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, PlaintextsAddCiphertextsTest) {
  PlaintextsAddCiphertexts(123, 2, 125);
  PlaintextsAddCiphertexts(123, -2, 121);
  PlaintextsAddCiphertexts(-123, 2, -121);
  PlaintextsAddCiphertexts(-123, -2, -125);
}

// PlaintextsAddCiphertextsInplace
void GPUTest::PlaintextsAddCiphertextsInplace(int128_t a, int128_t b,
                                              int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1;  // receive the GPU Encrypt results
  res1 = encryptor_->Encrypt(cts1);

  Ciphertext *cct1[1];
  cct1[0] = &res1[0];
  Span<Ciphertext> ct0 = absl::MakeSpan(cct1, 1);
  evaluator_->AddInplace(ct0, cts2);

  Ciphertext *ccts[1]{ct0[0]};
  ConstSpan<Ciphertext> cts =
      absl::MakeConstSpan(ccts, 1);  // create the constspan for GPU call
  std::vector<Plaintext> apts = decryptor_->Decrypt(cts);
  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, PlaintextsAddCiphertextsInplaceTest) {
  PlaintextsAddCiphertextsInplace(123, 2, 125);
  PlaintextsAddCiphertextsInplace(123, -2, 121);
  PlaintextsAddCiphertextsInplace(-123, 2, -121);
  PlaintextsAddCiphertextsInplace(-123, -2, -125);
  PlaintextsAddCiphertextsInplace(iMax, -2, iMax - 2);
}

// dec(cts1 * pts2) = pts1 * pts2
void GPUTest::CtsMulPts(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1;  // receive the GPU Encrypt results
  res1 = encryptor_->Encrypt(cts1);
  // vector -> ConstSpan
  Ciphertext *cct1[1]{&res1[0]};
  ConstSpan<Ciphertext> ct0 = absl::MakeConstSpan(cct1, 1);
  std::vector<Ciphertext> sum = evaluator_->Mul(ct0, cts2);

  // make the constspan for vector Decrypt
  Ciphertext *ccts[1]{&sum[0]};
  ConstSpan<Ciphertext> cts =
      absl::MakeConstSpan(ccts, 1);  // create the constspan for GPU call
  std::vector<Plaintext> apts = decryptor_->Decrypt(cts);
  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, CtsMulPtsTest) {
  CtsMulPts(2, 4, 8);
  CtsMulPts(-2, 4, -8);
  CtsMulPts(2, -4, -8);
  CtsMulPts(-2, -4, 8);
}

void GPUTest::PtsMulCts(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1;  // receive the GPU Encrypt results
  res1 = encryptor_->Encrypt(cts1);
  // vector -> ConstSpan
  Ciphertext *cct1[1]{&res1[0]};
  ConstSpan<Ciphertext> ct0 = absl::MakeConstSpan(cct1, 1);
  std::vector<Ciphertext> sum = evaluator_->Mul(cts2, ct0);

  // make the constspan for vector Decrypt
  Ciphertext *ccts[1]{&sum[0]};
  ConstSpan<Ciphertext> cts =
      absl::MakeConstSpan(ccts, 1);  // create the constspan for GPU call
  std::vector<Plaintext> apts = decryptor_->Decrypt(cts);
  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, PtsMulCtsTest) {
  PtsMulCts(2, 4, 8);
  PtsMulCts(-2, 4, -8);
  PtsMulCts(2, -4, -8);
  PtsMulCts(-2, -4, 8);
}

void GPUTest::PtsMulPts(int128_t a, int128_t b, int128_t c, int128_t d,
                        int128_t e, int128_t f) {
  Plaintext p11(a);
  Plaintext p12(b);
  Plaintext p21(c);
  Plaintext p22(d);
  Plaintext *ppts1[2]{&p11, &p12};
  Plaintext *ppts2[2]{&p21, &p22};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 2);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 2);

  std::vector<Plaintext> product = evaluator_->Mul(cts1, cts2);
  EXPECT_EQ(product[0], e);
  EXPECT_EQ(product[1], f);
}

TEST_F(GPUTest, PtsMulPtsTest) {
  PtsMulPts(5, 7, 8, 9, 40, 63);
  PtsMulPts(-5, 7, 8, -9, -40, -63);
  PtsMulPts(-5, -7, -8, -9, 40, 63);
}

void GPUTest::CtsMulPtsInplace(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1;  // receive the GPU Encrypt results
  res1 = encryptor_->Encrypt(cts1);

  // vector -> ConstSpan
  Ciphertext *cct1[1]{&res1[0]};
  Span<Ciphertext> ct0 = absl::MakeSpan(cct1, 1);
  evaluator_->MulInplace(ct0, cts2);

  // make the constSpan for vector Decrypt
  std::vector<Plaintext> apts = decryptor_->Decrypt(ct0);
  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, CtsMulPtsInplaceTest) {
  CtsMulPtsInplace(2, 4, 8);
  CtsMulPtsInplace(-2, 4, -8);
  CtsMulPtsInplace(2, -4, -8);
  CtsMulPtsInplace(-2, -4, 8);
}

void GPUTest::PtsMulPtsInplace(int128_t a, int128_t b, int128_t c, int128_t d,
                               int128_t e, int128_t f) {
  Plaintext p11(a);
  Plaintext p12(b);
  Plaintext p21(c);
  Plaintext p22(d);
  Plaintext *ppts1[2]{&p11, &p12};
  Plaintext *ppts2[2]{&p21, &p22};
  // make the constspan for vector Encrypt
  Span<Plaintext> cts1 = absl::MakeSpan(ppts1, 2);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 2);

  evaluator_->MulInplace(cts1, cts2);
  EXPECT_EQ(*cts1[0], e);
  EXPECT_EQ(*cts1[1], f);
}

TEST_F(GPUTest, PtsMulPtsInplaceTest) {
  PtsMulPtsInplace(5, 7, 8, 9, 40, 63);
  PtsMulPtsInplace(-5, 7, 8, -9, -40, -63);
  PtsMulPtsInplace(-5, -7, -8, -9, 40, 63);
}

/*                         Neg                              */

void GPUTest::CiphertextsNegate(int128_t a, int128_t b) {
  Plaintext p1(a);
  Plaintext *ppts[1]{&p1};
  Span<Plaintext> pts = absl::MakeSpan(ppts, 1);
  std::vector<Ciphertext> ctvec = encryptor_->Encrypt(pts);

  Ciphertext *ccts[1]{&ctvec[0]};
  Span<Ciphertext> cts = absl::MakeSpan(ccts, 1);
  std::vector<Ciphertext> ctNeg = evaluator_->Negate(cts);

  Ciphertext *ctArray[1]{&ctNeg[0]};
  Span<Ciphertext> cts_neg = absl::MakeSpan(ctArray, 1);
  std::vector<Plaintext> ptvec = decryptor_->Decrypt(cts_neg);

  EXPECT_EQ(ptvec[0], b);
}

TEST_F(GPUTest, CiphertextsNegateTest) {
  CiphertextsNegate(5, -5);
  CiphertextsNegate(-123, 123);
  CiphertextsNegate(0, 0);
  CiphertextsNegate(iMax, -1 * iMax);
}

void GPUTest::CiphertextsNegateInplace(int128_t a, int128_t b) {
  Plaintext p1(a);
  Plaintext *ppts[1]{&p1};
  Span<Plaintext> pts = absl::MakeSpan(ppts, 1);
  std::vector<Ciphertext> ctvec = encryptor_->Encrypt(pts);

  Ciphertext *ccts[1]{&ctvec[0]};
  Span<Ciphertext> cts = absl::MakeSpan(ccts, 1);
  evaluator_->NegateInplace(cts);

  std::vector<Plaintext> ptvec = decryptor_->Decrypt(cts);

  EXPECT_EQ(ptvec[0], b);
}

TEST_F(GPUTest, CiphertextsNegateInplaceTest) {
  CiphertextsNegateInplace(5, -5);
  CiphertextsNegateInplace(-123, 123);
  CiphertextsNegateInplace(0, 0);
}

/*                         Sub                              */

// CiphertextsSub
void GPUTest::CiphertextsSub(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1, res2;
  res1 = encryptor_->Encrypt(cts1);  // Encrypt: plaintext --> ciphertext
  res2 = encryptor_->Encrypt(cts2);

  Ciphertext *cct1[1]{&res1[0]};
  Ciphertext *cct2[1]{&res2[0]};
  ConstSpan<Ciphertext> ct0 = absl::MakeConstSpan(cct1, 1);
  ConstSpan<Ciphertext> ct1 = absl::MakeConstSpan(cct2, 1);
  std::vector<Ciphertext> sum =
      evaluator_->Sub(ct0, ct1);  // Sub: ciphertext - ciphertext

  // make the constspan for vector Decrypt
  Ciphertext *ccts[1]{&sum[0]};
  ConstSpan<Ciphertext> cts =
      absl::MakeConstSpan(ccts, 1);  // create the constspan for GPU call
  std::vector<Plaintext> apts = decryptor_->Decrypt(cts);

  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, CiphertextsSubTest) {
  CiphertextsSub(123, -7, 130);
  CiphertextsSub(-123, -7, -116);
  CiphertextsSub(123, 7, 116);
  CiphertextsSub(iLow, -1, iLow + 1);
}

void GPUTest::CtsSubPts(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> pts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> pts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1;
  res1 = encryptor_->Encrypt(pts1);  // Encrypt: plaintext --> ciphertext

  Ciphertext *cct1[1]{&res1[0]};
  ConstSpan<Ciphertext> ct0 = absl::MakeConstSpan(cct1, 1);
  std::vector<Ciphertext> sum =
      evaluator_->Sub(ct0, pts2);  // Sub: ciphertext - ciphertext

  // make the constspan for vector Decrypt
  Ciphertext *ccts[1]{&sum[0]};
  ConstSpan<Ciphertext> cts =
      absl::MakeConstSpan(ccts, 1);  // create the constspan for GPU call
  std::vector<Plaintext> apts = decryptor_->Decrypt(cts);

  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, CtsSubPtsTest) {
  CtsSubPts(123, -7, 130);
  CtsSubPts(-123, -7, -116);
  CtsSubPts(123, 7, 116);
}

void GPUTest::PtsSubCts(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> pts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> pts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res2;
  res2 = encryptor_->Encrypt(pts2);  // Encrypt: plaintext --> ciphertext

  Ciphertext *cct2[1]{&res2[0]};
  ConstSpan<Ciphertext> ct2 = absl::MakeConstSpan(cct2, 1);
  std::vector<Ciphertext> sum =
      evaluator_->Sub(pts1, ct2);  // Sub: ciphertext - ciphertext

  // make the constspan for vector Decrypt
  Ciphertext *ccts[1]{&sum[0]};
  ConstSpan<Ciphertext> cts =
      absl::MakeConstSpan(ccts, 1);  // create the constspan for GPU call
  std::vector<Plaintext> apts = decryptor_->Decrypt(cts);

  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, PtsSubCtsTest) {
  PtsSubCts(123, -7, 130);
  PtsSubCts(-123, -7, -116);
  PtsSubCts(123, 7, 116);
}

void GPUTest::PtsSubPts(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> pts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> pts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Plaintext> sum =
      evaluator_->Sub(pts1, pts2);  // Sub: ciphertext - ciphertext

  EXPECT_EQ(sum[0], c);
}

TEST_F(GPUTest, PtsSubPtsTest) {
  PtsSubPts(123, -7, 130);
  PtsSubPts(-123, -7, -116);
  PtsSubPts(123, 7, 116);
}

void GPUTest::CiphertextsSubInplace(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> cts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> cts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1, res2;
  res1 = encryptor_->Encrypt(cts1);  // Encrypt: plaintext --> ciphertext
  res2 = encryptor_->Encrypt(cts2);

  Ciphertext *cct1[1]{&res1[0]};
  Ciphertext *cct2[1]{&res2[0]};
  Span<Ciphertext> ct0 = absl::MakeSpan(cct1, 1);
  ConstSpan<Ciphertext> ct1 = absl::MakeConstSpan(cct2, 1);
  evaluator_->SubInplace(ct0, ct1);  // Sub: ciphertext - ciphertext

  std::vector<Plaintext> apts = decryptor_->Decrypt(ct0);

  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, CiphertextsSubInplaceTest) {
  CiphertextsSubInplace(123, -7, 130);
  CiphertextsSubInplace(-123, -7, -116);
  CiphertextsSubInplace(123, 7, 116);
}

void GPUTest::CtsSubPtsInplace(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  ConstSpan<Plaintext> pts1 = absl::MakeConstSpan(ppts1, 1);
  ConstSpan<Plaintext> pts2 = absl::MakeConstSpan(ppts2, 1);

  std::vector<Ciphertext> res1;
  res1 = encryptor_->Encrypt(pts1);  // Encrypt: plaintext --> ciphertext

  Ciphertext *cct1[1]{&res1[0]};
  Span<Ciphertext> ct0 = absl::MakeSpan(cct1, 1);
  evaluator_->SubInplace(ct0, pts2);  // Sub: ciphertext - ciphertext

  std::vector<Plaintext> apts = decryptor_->Decrypt(ct0);

  EXPECT_EQ(apts[0], c);
}

TEST_F(GPUTest, CtsSubPtsInplaceTest) {
  CtsSubPtsInplace(123, -7, 130);
  CtsSubPtsInplace(-123, -7, -116);
  CtsSubPtsInplace(123, 7, 116);
}

void GPUTest::PtsSubPtsInplace(int128_t a, int128_t b, int128_t c) {
  Plaintext p1(a);
  Plaintext p2(b);
  Plaintext *ppts1[1]{&p1};
  Plaintext *ppts2[1]{&p2};
  // make the constspan for vector Encrypt
  Span<Plaintext> pts1 = absl::MakeSpan(ppts1, 1);
  ConstSpan<Plaintext> pts2 = absl::MakeConstSpan(ppts2, 1);
  evaluator_->SubInplace(pts1, pts2);  // Sub: ciphertext - ciphertext

  EXPECT_EQ(*pts1[0], c);
}

TEST_F(GPUTest, PtsSubPtsInplaceTest) {
  PtsSubPtsInplace(123, -7, 130);
  PtsSubPtsInplace(-123, -7, -116);
  PtsSubPtsInplace(123, 7, 116);
}

}  // namespace heu::lib::algorithms::paillier_g::test
