// Copyright 2023 Clustar Technology Co., Ltd.
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

#include <chrono>

#include "gtest/gtest.h"

#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/paillier_operators.h"
#include "heu/library/algorithms/paillier_clustar_fpga/key_generator.h"
#include "heu/library/algorithms/paillier_clustar_fpga/utils/facility.h"
#include "heu/library/algorithms/paillier_clustar_fpga/vector_decryptor.h"
#include "heu/library/algorithms/paillier_clustar_fpga/vector_encryptor.h"
#include "heu/library/algorithms/paillier_clustar_fpga/vector_evaluator.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::test {

class CEvaluatorTest : public ::testing::TestWithParam<size_t> {
 protected:
  void SetUp() override {
    unsigned key_length = GetParam();
    KeyGenerator::Generate(key_length, &sk_, &pk_);
    encryptor_ = std::make_shared<Encryptor>(pk_);
    decryptor_ = std::make_shared<Decryptor>(pk_, sk_);
    evaluator_ = std::make_shared<Evaluator>(pk_);
  }

  template <typename T>
  ConstSpan<Plaintext> CleartextToConstSpan(
      std::vector<T>& input_vec, std::vector<Plaintext>& plain_vec,
      std::vector<Plaintext*>& plain_ptrs);

  template <typename T>
  Span<Plaintext> CleartextToSpan(std::vector<T>& input_vec,
                                  std::vector<Plaintext>& plain_vec,
                                  std::vector<Plaintext*>& plain_ptrs);

  // T: Ciphertext/Plaintext
  template <typename T>
  ConstSpan<T> TextToConstSpan(std::vector<T>& input_vec,
                               std::vector<T*>& text_ptrs);

  // T: Ciphertext/Plaintext
  template <typename T>
  Span<T> TextToSpan(std::vector<T>& input_vec, std::vector<T*>& text_ptrs);

 protected:
  SecretKey sk_;
  PublicKey pk_;
  std::shared_ptr<Encryptor> encryptor_;
  std::shared_ptr<Decryptor> decryptor_;
  std::shared_ptr<Evaluator> evaluator_;
};

INSTANTIATE_TEST_SUITE_P(SubTest, CEvaluatorTest,
                         ::testing::Values(512, 1024, 2048));

template <typename T>
ConstSpan<Plaintext> CEvaluatorTest::CleartextToConstSpan(
    std::vector<T>& input_vec, std::vector<Plaintext>& plain_vec,
    std::vector<Plaintext*>& plain_ptrs) {
  size_t vec_size = input_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    plain_vec.push_back(Plaintext(input_vec[i]));
  }

  CMonoFacility::ValueVecToPtrVec(plain_vec, plain_ptrs);

  auto plain_span = absl::MakeConstSpan(plain_ptrs.data(), vec_size);
  return plain_span;
}

template <typename T>
Span<Plaintext> CEvaluatorTest::CleartextToSpan(
    std::vector<T>& input_vec, std::vector<Plaintext>& plain_vec,
    std::vector<Plaintext*>& plain_ptrs) {
  size_t vec_size = input_vec.size();
  for (size_t i = 0; i < vec_size; i++) {
    plain_vec.push_back(Plaintext(input_vec[i]));
  }

  CMonoFacility::ValueVecToPtrVec(plain_vec, plain_ptrs);

  auto plain_span = absl::MakeSpan(plain_ptrs.data(), vec_size);
  return plain_span;
}

template <typename T>
ConstSpan<T> CEvaluatorTest::TextToConstSpan(std::vector<T>& input_vec,
                                             std::vector<T*>& text_ptrs) {
  CMonoFacility::ValueVecToPtrVec(input_vec, text_ptrs);
  auto text_span = absl::MakeConstSpan(text_ptrs.data(), text_ptrs.size());
  return text_span;
}

template <typename T>
Span<T> CEvaluatorTest::TextToSpan(std::vector<T>& input_vec,
                                   std::vector<T*>& text_ptrs) {
  CMonoFacility::ValueVecToPtrVec(input_vec, text_ptrs);
  auto text_span = absl::MakeSpan(text_ptrs.data(), text_ptrs.size());
  return text_span;
}

TEST_P(CEvaluatorTest, Randomize) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> expect_res{-123, 456, -789, 0, -1, 10001};

  std::vector<Plaintext> a_plain_vec;
  auto vec_size = a_vec.size();
  a_plain_vec.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    a_plain_vec[i] = Plaintext(a_vec[i]);
  }

  // encrpt
  std::vector<Plaintext*> a_plain_ptrs;
  CMonoFacility::ValueVecToPtrVec(a_plain_vec, a_plain_ptrs);
  auto a_plain_span = absl::MakeConstSpan(a_plain_ptrs.data(), vec_size);
  auto a_cipher_vec = encryptor_->Encrypt(a_plain_span);

  std::vector<Ciphertext*> a_cipher_vec_ptrs;
  CMonoFacility::ValueVecToPtrVec(a_cipher_vec, a_cipher_vec_ptrs);
  auto a_cipher_span =
      absl::MakeSpan(a_cipher_vec_ptrs.data(), a_cipher_vec_ptrs.size());

  // randomize
  evaluator_->Randomize(a_cipher_span);

  // decrypt
  auto a_const_cipher_span =
      absl::MakeSpan(a_cipher_vec_ptrs.data(), a_cipher_vec_ptrs.size());
  std::vector<Plaintext> res_plain_vec =
      decryptor_->Decrypt(a_const_cipher_span);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_plain_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherAddCipher) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] + b_vec[i];
  }

  // encrypt
  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_const_cipher_span = TextToConstSpan(a_cipher_vec, a_ciphertext_ptrs);

  // encrypt b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);
  auto b_cipher_vec = encryptor_->Encrypt(b_const_plain_span);
  std::vector<Ciphertext*> b_ciphertext_ptrs;
  auto b_cipher_span = TextToConstSpan(b_cipher_vec, b_ciphertext_ptrs);

  // add
  std::vector<Ciphertext> res_cipher =
      evaluator_->Add(a_const_cipher_span, b_cipher_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherAddPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};
  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] + b_vec[i];
  }

  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_const_cipher_span = TextToConstSpan(a_cipher_vec, a_ciphertext_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // add
  std::vector<Ciphertext> res_cipher =
      evaluator_->Add(a_const_cipher_span, b_const_plain_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainAddCipher) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};
  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] + b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // encrypt b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);
  auto b_cipher_vec = encryptor_->Encrypt(b_const_plain_span);
  std::vector<Ciphertext*> b_ciphertext_ptrs;
  auto b_const_cipher_span = TextToConstSpan(b_cipher_vec, b_ciphertext_ptrs);

  // add
  std::vector<Ciphertext> res_cipher =
      evaluator_->Add(a_const_plain_span, b_const_cipher_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainAddPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};
  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] + b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // add
  std::vector<Plaintext> res_plain =
      evaluator_->Add(a_const_plain_span, b_const_plain_span);

  // Check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_plain[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherInplaceAddCipher) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};
  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] + b_vec[i];
  }

  // encrypt
  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_cipher_span = TextToSpan(a_cipher_vec, a_ciphertext_ptrs);

  // encrypt b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);
  auto b_cipher_vec = encryptor_->Encrypt(b_const_plain_span);
  std::vector<Ciphertext*> b_ciphertext_ptrs;
  auto b_const_cipher_span = TextToConstSpan(b_cipher_vec, b_ciphertext_ptrs);

  // add in place
  evaluator_->AddInplace(a_cipher_span, b_const_cipher_span);

  // decrypt
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(a_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherInplaceAddPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};
  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] + b_vec[i];
  }

  // encrypt
  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_cipher_span = TextToSpan(a_cipher_vec, a_ciphertext_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // add in place
  evaluator_->AddInplace(a_cipher_span, b_const_plain_span);

  // decrypt
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(a_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainInplaceAddPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};
  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] + b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_plain_span = CleartextToSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // add in place
  evaluator_->AddInplace(a_plain_span, b_const_plain_span);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(*a_plain_span[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherSubCipher) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] - b_vec[i];
  }

  // encrypt
  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_const_cipher_span = TextToConstSpan(a_cipher_vec, a_ciphertext_ptrs);

  // encrypt b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);
  auto b_cipher_vec = encryptor_->Encrypt(b_const_plain_span);
  std::vector<Ciphertext*> b_ciphertext_ptrs;
  auto b_const_cipher_span = TextToConstSpan(b_cipher_vec, b_ciphertext_ptrs);

  // sub
  std::vector<Ciphertext> res_cipher =
      evaluator_->Sub(a_const_cipher_span, b_const_cipher_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherSubPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] - b_vec[i];
  }

  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_const_cipher_span = TextToConstSpan(a_cipher_vec, a_ciphertext_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // sub
  std::vector<Ciphertext> res_cipher =
      evaluator_->Sub(a_const_cipher_span, b_const_plain_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainSubCipher) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] - b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // encrypt b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);
  auto b_cipher_vec = encryptor_->Encrypt(b_const_plain_span);
  std::vector<Ciphertext*> b_ciphertext_ptrs;
  auto b_const_cipher_span = TextToConstSpan(b_cipher_vec, b_ciphertext_ptrs);

  // sub
  std::vector<Ciphertext> res_cipher =
      evaluator_->Sub(a_const_plain_span, b_const_cipher_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainSubPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] - b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // sub
  std::vector<Plaintext> res_plain =
      evaluator_->Sub(a_const_plain_span, b_const_plain_span);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_plain[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherInplaceSubCipher) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] - b_vec[i];
  }

  // encrypt
  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_cipher_span = TextToSpan(a_cipher_vec, a_ciphertext_ptrs);

  // encrypt b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);
  auto b_cipher_vec = encryptor_->Encrypt(b_const_plain_span);
  std::vector<Ciphertext*> b_ciphertext_ptrs;
  auto b_const_cipher_span = TextToConstSpan(b_cipher_vec, b_ciphertext_ptrs);

  // sub
  evaluator_->SubInplace(a_cipher_span, b_const_cipher_span);

  // decrypt
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(a_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherInplaceSubPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] - b_vec[i];
  }

  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_cipher_span = TextToSpan(a_cipher_vec, a_ciphertext_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // sub
  evaluator_->SubInplace(a_cipher_span, b_const_plain_span);

  // decrypt
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(a_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainInplaceSubPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] - b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_plain_span = CleartextToSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // sub
  evaluator_->SubInplace(a_plain_span, b_const_plain_span);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(*a_plain_span[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherMulPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999, 1000, 0};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] * b_vec[i];
  }

  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_const_cipher_span = TextToConstSpan(a_cipher_vec, a_ciphertext_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // mul
  std::vector<Ciphertext> res_cipher =
      evaluator_->Mul(a_const_cipher_span, b_const_plain_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherMulOnePlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> b_vec{456};

  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] * b_vec[0];
  }

  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_const_cipher_span = TextToConstSpan(a_cipher_vec, a_ciphertext_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // mul
  std::vector<Ciphertext> res_cipher =
      evaluator_->Mul(a_const_cipher_span, b_const_plain_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, OneCipherMulPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999, 1000, 0};

  std::vector<int32_t> expect_res;
  size_t vec_size = b_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[0] * b_vec[i];
  }

  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_const_cipher_span = TextToConstSpan(a_cipher_vec, a_ciphertext_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // mul
  std::vector<Ciphertext> res_cipher =
      evaluator_->Mul(a_const_cipher_span, b_const_plain_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainMulCipher) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999, 1000, 0};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] * b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // encrypt b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);
  auto b_cipher_vec = encryptor_->Encrypt(b_const_plain_span);
  std::vector<Ciphertext*> b_ciphertext_ptrs;
  auto b_const_cipher_span = TextToConstSpan(b_cipher_vec, b_ciphertext_ptrs);

  // mul
  std::vector<Ciphertext> res_cipher =
      evaluator_->Mul(a_const_plain_span, b_const_cipher_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainMulOneCipher) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> b_vec{-9999};

  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] * b_vec[0];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // encrypt b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);
  auto b_cipher_vec = encryptor_->Encrypt(b_const_plain_span);
  std::vector<Ciphertext*> b_ciphertext_ptrs;
  auto b_const_cipher_span = TextToConstSpan(b_cipher_vec, b_ciphertext_ptrs);

  // mul
  std::vector<Ciphertext> res_cipher =
      evaluator_->Mul(a_const_plain_span, b_const_cipher_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, OnePlainMulCipher) {
  // prepare
  std::vector<int32_t> a_vec{10001};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999, 1000, 0};

  std::vector<int32_t> expect_res;
  size_t vec_size = b_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[0] * b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // encrypt b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);
  auto b_cipher_vec = encryptor_->Encrypt(b_const_plain_span);
  std::vector<Ciphertext*> b_ciphertext_ptrs;
  auto b_const_cipher_span = TextToConstSpan(b_cipher_vec, b_ciphertext_ptrs);

  // mul
  std::vector<Ciphertext> res_cipher =
      evaluator_->Mul(a_const_plain_span, b_const_cipher_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainMulPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999, 1000, 0};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] * b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // mul
  std::vector<Plaintext> res_plain =
      evaluator_->Mul(a_const_plain_span, b_const_plain_span);

  // Check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_plain[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainMulOnePlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> b_vec{789};

  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] * b_vec[0];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // mul
  std::vector<Plaintext> res_plain =
      evaluator_->Mul(a_const_plain_span, b_const_plain_span);

  // Check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_plain[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, OnePlainMulPlain) {
  // prepare
  std::vector<int32_t> a_vec{456};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999, 1000, 0};

  std::vector<int32_t> expect_res;
  size_t vec_size = b_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[0] * b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // mul
  std::vector<Plaintext> res_plain =
      evaluator_->Mul(a_const_plain_span, b_const_plain_span);

  // Check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_plain[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherInplaceMulPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999, 1000, 0};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] * b_vec[i];
  }

  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_cipher_span = TextToSpan(a_cipher_vec, a_ciphertext_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // mul
  evaluator_->MulInplace(a_cipher_span, b_const_plain_span);

  // decrypt
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(a_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, CipherInplaceMulOnePlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> b_vec{-123};

  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] * b_vec[0];
  }

  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_cipher_span = TextToSpan(a_cipher_vec, a_ciphertext_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // mul
  evaluator_->MulInplace(a_cipher_span, b_const_plain_span);

  // decrypt
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(a_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainInplaceMulPlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> b_vec{456, 789, -123, 0, 1, -9999, 1000, 0};

  ASSERT_EQ(a_vec.size(), b_vec.size());
  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] * b_vec[i];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_plain_span = CleartextToSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // mul
  std::vector<Plaintext> res_plain =
      evaluator_->Mul(a_plain_span, b_const_plain_span);

  // Check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_plain[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, PlainInplaceMulOnePlain) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> b_vec{456};

  std::vector<int32_t> expect_res;
  size_t vec_size = a_vec.size();
  expect_res.resize(vec_size);
  for (size_t i = 0; i < vec_size; i++) {
    expect_res[i] = a_vec[i] * b_vec[0];
  }

  // plaintex a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_plain_span = CleartextToSpan(a_vec, a_plain_vec, a_plain_ptrs);

  // plaintex b_vec
  std::vector<Plaintext> b_plain_vec;
  std::vector<Plaintext*> b_plain_ptrs;
  auto b_const_plain_span =
      CleartextToConstSpan(b_vec, b_plain_vec, b_plain_ptrs);

  // mul
  std::vector<Plaintext> res_plain =
      evaluator_->Mul(a_plain_span, b_const_plain_span);

  // Check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_plain[i], Plaintext(expect_res[i]));
  }
}

TEST_P(CEvaluatorTest, Negate) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> expect_vec{123, -456, 789, 0, 1, -10001, 0, 1002};
  size_t vec_size = a_vec.size();
  EXPECT_EQ(vec_size, expect_vec.size());

  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_const_cipher_span = TextToConstSpan(a_cipher_vec, a_ciphertext_ptrs);

  // negate
  std::vector<Ciphertext> res_cipher = evaluator_->Negate(a_const_cipher_span);

  // decrypt
  std::vector<Ciphertext*> res_ciphertext_ptrs;
  auto res_cipher_span = TextToConstSpan(res_cipher, res_ciphertext_ptrs);
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(res_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_vec[i]));
  }
}

TEST_P(CEvaluatorTest, NegateInplace) {
  // prepare
  std::vector<int32_t> a_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  std::vector<int32_t> expect_vec{123, -456, 789, 0, 1, -10001, 0, 1002};
  size_t vec_size = a_vec.size();
  EXPECT_EQ(vec_size, expect_vec.size());

  // encrypt a_vec
  std::vector<Plaintext> a_plain_vec;
  std::vector<Plaintext*> a_plain_ptrs;
  auto a_const_plain_span =
      CleartextToConstSpan(a_vec, a_plain_vec, a_plain_ptrs);
  auto a_cipher_vec = encryptor_->Encrypt(a_const_plain_span);
  std::vector<Ciphertext*> a_ciphertext_ptrs;
  auto a_cipher_span = TextToSpan(a_cipher_vec, a_ciphertext_ptrs);

  // negate
  evaluator_->NegateInplace(a_cipher_span);

  // decrypt
  std::vector<Plaintext> res_vec = decryptor_->Decrypt(a_cipher_span);
  EXPECT_EQ(res_vec.size(), vec_size);

  // check
  for (size_t i = 0; i < vec_size; i++) {
    EXPECT_EQ(res_vec[i], Plaintext(expect_vec[i]));
  }
}

TEST_P(CEvaluatorTest, CalcSum) {
  // prepare
  std::vector<int32_t> input_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  int32_t expected_result = 0;
  for (const auto& elem : input_vec) {
    expected_result += elem;
  }

  // encrypt input_vec
  std::vector<Plaintext> input_plain_vec;
  std::vector<Plaintext*> input_plain_ptrs;
  auto input_const_plain_span =
      CleartextToConstSpan(input_vec, input_plain_vec, input_plain_ptrs);
  auto input_cipher_vec = encryptor_->Encrypt(input_const_plain_span);

  std::vector<Ciphertext*> input_ciphertext_ptrs;
  auto input_const_cipher_span =
      TextToConstSpan(input_cipher_vec, input_ciphertext_ptrs);

  Ciphertext result_cipher;

  // sum
  evaluator_->CalcSum(&result_cipher, input_const_cipher_span);

  // decrypt
  Plaintext res_plain;
  decryptor_->Decrypt({&result_cipher}, {&res_plain});

  // check
  EXPECT_EQ(res_plain, Plaintext(expected_result));
}

TEST_P(CEvaluatorTest, PlaintextCalcSum) {
  // prepare
  std::vector<int32_t> input_vec{-123, 456, -789, 0, -1, 10001, 0, -1002};
  size_t input_size = input_vec.size();
  int32_t expected_result = 0;
  for (const auto& elem : input_vec) {
    expected_result += elem;
  }

  // tranform to plaintext
  std::vector<Plaintext> input_plain_vec;
  input_plain_vec.reserve(input_size);
  for (size_t i = 0; i < input_size; i++) {
    input_plain_vec.push_back(Plaintext(input_vec[i]));
  }

  std::vector<Plaintext*> input_plain_ptrs;
  CMonoFacility::ValueVecToPtrVec(input_plain_vec, input_plain_ptrs);

  // calc sum
  Plaintext plain_sum;
  evaluator_->CalcSum(&plain_sum, input_plain_ptrs);

  // check results
  EXPECT_EQ(Plaintext(expected_result), plain_sum);
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::test
