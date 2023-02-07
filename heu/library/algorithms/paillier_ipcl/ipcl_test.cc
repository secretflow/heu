// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "heu/library/algorithms/paillier_ipcl/ipcl.h"

#include "gtest/gtest.h"
#include "yacl/base/int128.h"

#include "heu/library/algorithms/paillier_ipcl/utils.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_ipcl::test {

class IPCLTest : public ::testing::Test {
 protected:
  void SetUp() override {
    KeyGenerator::Generate(2048, &sk_, &pk_);
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

TEST_F(IPCLTest, GetSet) {
  int32_t a1 = -123456789;
  Plaintext pt1;
  pt1.Set(a1);
  int32_t b1 = pt1.Get<int32_t>();
  EXPECT_EQ(a1, b1);

  int64_t a2 = -123456789123456789;
  Plaintext pt2;
  pt2.Set(a2);
  int64_t b2 = pt2.Get<int64_t>();
  EXPECT_EQ(a2, b2);

  int128_t a3 = -123456789123456789;
  Plaintext pt3;
  pt3.Set(a3);
  int128_t b3 = pt3.Get<int128_t>();
  EXPECT_EQ(a3, b3);

  int16_t a4 = -32000;
  Plaintext pt4;
  pt4.Set(a4);
  int16_t b4 = pt4.Get<int16_t>();
  EXPECT_EQ(a4, b4);

  int8_t a5 = -123;
  Plaintext pt5;
  pt5.Set(a5);
  int8_t b5 = pt5.Get<int8_t>();
  EXPECT_EQ(a5, b5);

  uint32_t a6 = 123456789;
  Plaintext pt6;
  pt6.Set(a6);
  uint32_t b6 = pt6.Get<uint32_t>();
  EXPECT_EQ(a6, b6);

  uint64_t a7 = 123456789123456789;
  Plaintext pt7;
  pt7.Set(a7);
  uint64_t b7 = pt7.Get<uint64_t>();
  EXPECT_EQ(a7, b7);

  uint128_t a8 = 123456789123456789;
  Plaintext pt8;
  pt8.Set(a8);
  uint128_t b8 = pt8.Get<uint128_t>();
  EXPECT_EQ(a8, b8);

  uint16_t a9 = 32000;
  Plaintext pt9;
  pt9.Set(a9);
  uint16_t b9 = pt9.Get<uint16_t>();
  EXPECT_EQ(a9, b9);

  uint8_t a10 = 123;
  Plaintext pt10;
  pt10.Set(a10);
  uint8_t b10 = pt10.Get<uint8_t>();
  EXPECT_EQ(a10, b10);

  std::string a11 = "0x1234abcd";
  int32_t expect = 305441741;
  Plaintext pt11;
  pt11.Set(a11, 16);
  int32_t b11 = pt11.Get<int32_t>();
  EXPECT_EQ(b11, expect);

  std::string a12 = "123456789";
  expect = 123456789;
  Plaintext pt12;
  pt12.Set(a12, 10);
  int32_t b12 = pt12.Get<int32_t>();
  EXPECT_EQ(b12, expect);
}

TEST_F(IPCLTest, ToBytes) {
  Plaintext a;
  a.Set(0x1234);
  auto buf = a.ToBytes(2, Endian::little);
  EXPECT_EQ(buf.data<char>()[0], 0x34);
  EXPECT_EQ(buf.data<char>()[1], 0x12);

  buf = a.ToBytes(2, Endian::big);
  EXPECT_EQ(buf.data<char>()[0], 0x12);
  EXPECT_EQ(buf.data<char>()[1], 0x34);

  a.Set(0x123456);
  buf = a.ToBytes(2, Endian::native);
  EXPECT_EQ(buf.data<uint16_t>()[0], 0x3456);

  // TODO: the following case failed.
  // a.Set(-1);
  // EXPECT_EQ(a.ToBytes(10, Endian::little), a.ToBytes(10, Endian::big));
}

TEST_F(IPCLTest, EncDec) {
  std::vector<int32_t> a_vec{-234, 890, -567, 0};
  std::vector<int32_t> expect_res{-234, 890, -567, 0};
  std::vector<Plaintext> a_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);
  std::vector<Ciphertext *> a_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(a_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, CTPlusCT) {
  std::vector<int32_t> a_vec{123, 456, 789};
  std::vector<int32_t> b_vec{-234, 890, -567};
  std::vector<int32_t> expect_res{-111, 1346, 222};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);
  auto b_ct_vec = encryptor_->Encrypt(b_pt_span);
  std::vector<Ciphertext *> a_ct_pts;
  std::vector<Ciphertext *> b_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  ValueVecToPtsVec(b_ct_vec, b_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);
  auto b_ct_span = absl::MakeConstSpan(b_ct_pts.data(), vec_size);
  std::vector<Ciphertext> res_ct_vec = evaluator_->Add(a_ct_span, b_ct_span);

  std::vector<Ciphertext *> res_ct_pts;
  ValueVecToPtsVec(res_ct_vec, res_ct_pts);
  auto res_ct_span = absl::MakeConstSpan(res_ct_pts.data(), vec_size);
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(res_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, CTPlusCTInplace) {
  std::vector<int32_t> a_vec{-123, 456, -789};
  std::vector<int32_t> b_vec{234, -890, 567};
  std::vector<int32_t> expect_res{111, -434, -222};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);
  auto b_ct_vec = encryptor_->Encrypt(b_pt_span);
  std::vector<Ciphertext *> a_ct_pts;
  std::vector<Ciphertext *> b_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  ValueVecToPtsVec(b_ct_vec, b_ct_pts);
  auto a_ct_span = absl::MakeSpan(a_ct_pts.data(), vec_size);
  auto b_ct_span = absl::MakeConstSpan(b_ct_pts.data(), vec_size);
  evaluator_->AddInplace(a_ct_span, b_ct_span);
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(a_ct_span);

  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, CTPlusPT) {
  std::vector<int32_t> a_vec{-123, 456, -789};
  std::vector<int32_t> b_vec{234, -890, 567};
  std::vector<int32_t> expect_res{111, -434, -222};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);

  std::vector<Ciphertext *> a_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);

  std::vector<Ciphertext> res_ct_vec = evaluator_->Add(a_ct_span, b_pt_span);

  std::vector<Ciphertext *> res_ct_pts;
  ValueVecToPtsVec(res_ct_vec, res_ct_pts);
  auto res_ct_span = absl::MakeConstSpan(res_ct_pts.data(), vec_size);
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(res_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, CTPlusPTInplace) {
  std::vector<int32_t> a_vec{-123, 456, -789};
  std::vector<int32_t> b_vec{234, -890, 567};
  std::vector<int32_t> expect_res{111, -434, -222};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);

  std::vector<Ciphertext *> a_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);

  evaluator_->AddInplace(a_ct_span, b_pt_span);
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(a_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, PTPlusPT) {
  std::vector<int32_t> a_vec{-123, 456, -789};
  std::vector<int32_t> b_vec{234, -890, 567};
  std::vector<int32_t> expect_res{111, -434, -222};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);

  auto result = evaluator_->Add(a_pt_span, b_pt_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)result[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, PTPlusPTInplace) {
  std::vector<int32_t> a_vec{-123, 456, -789};
  std::vector<int32_t> b_vec{234, -890, 567};
  std::vector<int32_t> expect_res{111, -434, -222};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);

  evaluator_->AddInplace(a_pt_span, b_pt_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)*a_pt_span[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, CTSubCT) {
  std::vector<int32_t> a_vec{123, 456, 789};
  std::vector<int32_t> b_vec{-234, 890, -567};
  std::vector<int32_t> expect_res{357, -434, 1356};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);
  auto b_ct_vec = encryptor_->Encrypt(b_pt_span);
  std::vector<Ciphertext *> a_ct_pts;
  std::vector<Ciphertext *> b_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  ValueVecToPtsVec(b_ct_vec, b_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);
  auto b_ct_span = absl::MakeConstSpan(b_ct_pts.data(), vec_size);
  std::vector<Ciphertext> res_ct_vec = evaluator_->Sub(a_ct_span, b_ct_span);

  std::vector<Ciphertext *> res_ct_pts;
  ValueVecToPtsVec(res_ct_vec, res_ct_pts);
  auto res_ct_span = absl::MakeConstSpan(res_ct_pts.data(), vec_size);
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(res_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, CTSubPT) {
  std::vector<int32_t> a_vec{123, 456, 789};
  std::vector<int32_t> b_vec{-234, 890, -567};
  std::vector<int32_t> expect_res{357, -434, 1356};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);

  std::vector<Ciphertext *> a_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);
  std::vector<Ciphertext> res_ct_vec = evaluator_->Sub(a_ct_span, b_pt_span);
  std::vector<Ciphertext *> res_ct_pts;
  ValueVecToPtsVec(res_ct_vec, res_ct_pts);
  auto res_ct_span = absl::MakeConstSpan(res_ct_pts.data(), vec_size);
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(res_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, PTSubCT) {
  std::vector<int32_t> a_vec{123, 456, 789};
  std::vector<int32_t> b_vec{-234, 890, -567};
  std::vector<int32_t> expect_res{357, -434, 1356};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);
  auto b_ct_vec = encryptor_->Encrypt(b_pt_span);

  std::vector<Ciphertext *> b_ct_pts;
  ValueVecToPtsVec(b_ct_vec, b_ct_pts);
  auto b_ct_span = absl::MakeConstSpan(b_ct_pts.data(), vec_size);
  std::vector<Ciphertext> res_ct_vec = evaluator_->Sub(a_pt_span, b_ct_span);
  std::vector<Ciphertext *> res_ct_pts;
  ValueVecToPtsVec(res_ct_vec, res_ct_pts);
  auto res_ct_span = absl::MakeConstSpan(res_ct_pts.data(), vec_size);
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(res_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, PTSubPT) {
  std::vector<int32_t> a_vec{123, 456, 789};
  std::vector<int32_t> b_vec{-234, 890, -567};
  std::vector<int32_t> expect_res{357, -434, 1356};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);

  std::vector<Plaintext> res_pt_vec = evaluator_->Sub(a_pt_span, b_pt_span);

  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, CTSubCTInplace) {
  std::vector<int32_t> a_vec{123, 456, 789};
  std::vector<int32_t> b_vec{-234, 890, -567};
  std::vector<int32_t> expect_res{357, -434, 1356};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);
  auto b_ct_vec = encryptor_->Encrypt(b_pt_span);
  std::vector<Ciphertext *> a_ct_pts;
  std::vector<Ciphertext *> b_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  ValueVecToPtsVec(b_ct_vec, b_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);
  auto b_ct_span = absl::MakeConstSpan(b_ct_pts.data(), vec_size);
  evaluator_->SubInplace(a_ct_span, b_ct_span);

  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(a_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, CTMultiplyPT) {
  std::vector<int32_t> a_vec{123, -456, -789};
  std::vector<int32_t> b_vec{-50, 40, 30};
  std::vector<int32_t> expect_res{-6150, -18240, -23670};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  for (size_t i = 0; i < a_vec.size(); i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
  }
  for (size_t i = 0; i < b_vec.size(); i++) {
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), a_vec.size());
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), b_vec.size());
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);

  std::vector<Ciphertext *> a_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), a_vec.size());

  std::vector<Ciphertext> res_ct_vec = evaluator_->Mul(a_ct_span, b_pt_span);

  std::vector<Ciphertext *> res_ct_pts;
  ValueVecToPtsVec(res_ct_vec, res_ct_pts);
  auto res_ct_span = absl::MakeConstSpan(res_ct_pts.data(), res_ct_pts.size());
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(res_ct_span);
  for (size_t i = 0; i < res_ct_pts.size(); i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, CTMultiplyPTInplace) {
  std::vector<int32_t> a_vec{123, -456, -789};
  std::vector<int32_t> b_vec{-50};
  std::vector<int32_t> expect_res{-6150, 22800, 39450};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  for (size_t i = 0; i < a_vec.size(); i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
  }
  for (size_t i = 0; i < b_vec.size(); i++) {
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), a_pt_pts.size());
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), b_pt_pts.size());
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);

  std::vector<Ciphertext *> a_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), a_ct_pts.size());

  evaluator_->MulInplace(a_ct_span, b_pt_span);
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(a_ct_span);
  for (size_t i = 0; i < res_pt_vec.size(); i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, PTMultiplyCT) {
  std::vector<int32_t> a_vec{-123, -456, 789};
  std::vector<int32_t> b_vec{-50, 40, -30};
  std::vector<int32_t> expect_res{6150, -18240, -23670};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  for (size_t i = 0; i < a_vec.size(); i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
  }
  for (size_t i = 0; i < b_vec.size(); i++) {
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), a_vec.size());
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), b_vec.size());
  auto b_ct_vec = encryptor_->Encrypt(b_pt_span);

  std::vector<Ciphertext *> b_ct_pts;
  ValueVecToPtsVec(b_ct_vec, b_ct_pts);
  auto b_ct_span = absl::MakeConstSpan(b_ct_pts.data(), b_vec.size());

  std::vector<Ciphertext> res_ct_vec = evaluator_->Mul(a_pt_span, b_ct_span);

  std::vector<Ciphertext *> res_ct_pts;
  ValueVecToPtsVec(res_ct_vec, res_ct_pts);
  auto res_ct_span = absl::MakeConstSpan(res_ct_pts.data(), res_ct_pts.size());
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(res_ct_span);
  for (size_t i = 0; i < res_pt_vec.size(); i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, PTMultiplyPT) {
  std::vector<int32_t> a_vec{-123, -456, 789};
  std::vector<int32_t> b_vec{-50, 40, -30};
  std::vector<int32_t> expect_res{6150, -18240, -23670};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);
  std::vector<Plaintext> res_pt_vec = evaluator_->Mul(a_pt_span, b_pt_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, PTMultiplyPTInplace) {
  std::vector<int32_t> a_vec{-123, -456, 789};
  std::vector<int32_t> b_vec{-50, 40, -30};
  std::vector<int32_t> expect_res{6150, -18240, -23670};

  std::vector<Plaintext> a_pt_vec;
  std::vector<Plaintext> b_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
    b_pt_vec.push_back(Plaintext(b_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  std::vector<Plaintext *> b_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  ValueVecToPtsVec(b_pt_vec, b_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto b_pt_span = absl::MakeConstSpan(b_pt_pts.data(), vec_size);

  evaluator_->MulInplace(a_pt_span, b_pt_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)*a_pt_span[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, Negate) {
  std::vector<int32_t> a_vec{123, 456};
  std::vector<int32_t> expect_res{-123, -456};
  std::vector<Plaintext> a_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);
  std::vector<Ciphertext *> a_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);

  std::vector<Ciphertext> res_ct_vec = evaluator_->Negate(a_ct_span);

  std::vector<Ciphertext *> res_ct_pts;
  ValueVecToPtsVec(res_ct_vec, res_ct_pts);
  auto res_ct_span = absl::MakeConstSpan(res_ct_pts.data(), vec_size);
  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(res_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, NegateInplace) {
  std::vector<int32_t> a_vec{123, 456};
  std::vector<int32_t> expect_res{-123, -456};
  std::vector<Plaintext> a_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);
  std::vector<Ciphertext *> a_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);

  evaluator_->NegateInplace(a_ct_span);

  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(a_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expect_res[i]));
  }
}

TEST_F(IPCLTest, Randomize) {
  std::vector<int32_t> a_vec{123, -456, 0};
  std::vector<int32_t> expected_res{123, -456, 0};
  std::vector<Plaintext> a_pt_vec;
  auto vec_size = a_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);
  std::vector<Ciphertext *> a_ct_pts;
  ValueVecToPtsVec(a_ct_vec, a_ct_pts);
  auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);

  evaluator_->Randomize(a_ct_span);

  std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(a_ct_span);
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ((BigNumber)res_pt_vec[i], BigNumber(expected_res[i]));
  }
}

TEST_F(IPCLTest, CTSerializeDeserialize) {
  std::vector<int32_t> a_vec{-234, 890, 0};
  auto vec_size = a_vec.size();
  std::vector<Plaintext> a_pt_vec;
  for (size_t i = 0; i < vec_size; i++) {
    a_pt_vec.push_back(Plaintext(a_vec[i]));
  }
  std::vector<Plaintext *> a_pt_pts;
  ValueVecToPtsVec(a_pt_vec, a_pt_pts);
  auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
  auto a_ct_vec = encryptor_->Encrypt(a_pt_span);
  std::vector<yacl::Buffer> buf_vec;
  for (size_t i = 0; i < a_ct_vec.size(); i++) {
    buf_vec.push_back(a_ct_vec[i].Serialize());
  }
  for (size_t i = 0; i < a_ct_vec.size(); i++) {
    yacl::ByteContainerView buf_view(buf_vec[i]);
    Ciphertext res;
    res.Deserialize(buf_view);
    EXPECT_EQ(res, a_ct_vec[i]);
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
}  // namespace heu::lib::algorithms::paillier_ipcl::test
