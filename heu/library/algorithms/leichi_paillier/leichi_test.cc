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

#include <future>
#include <random>

#include "gtest/gtest.h"
#include "heu/library/algorithms/leichi_paillier/vector_encryptor.h"
#include "heu/library/algorithms/leichi_paillier/vector_decryptor.h"
#include "heu/library/algorithms/leichi_paillier/key_generator.h"
#include "heu/library/algorithms/leichi_paillier/vector_evaluator.h"

namespace heu::lib::algorithms::leichi_paillier::test {

    class LEICHITest : public testing::Test {
        protected:
          void SetUp() override {
            KeyGenerator::Generate(2048, &sk_, &pk_);
            encryptor_ = std::make_shared<Encryptor>(pk_);
            evaluator_ = std::make_shared<Evaluator>(pk_);
            decryptor_ = std::make_shared<Decryptor>(pk_, sk_);
          }

        protected:
          SecretKey sk_;
          PublicKey pk_;
          std::shared_ptr<Encryptor> encryptor_;
          std::shared_ptr<Evaluator> evaluator_;
          std::shared_ptr<Decryptor> decryptor_;
    };

    int CompareBignum(const BIGNUM* bn1, const BIGNUM* bn2) {
        return BN_cmp(bn1, bn2);
    }

  TEST_F(LEICHITest, DISABLE_EncDec) {
        Encryptor encryptor(pk_);
        Decryptor decryptor(pk_, sk_);
        std::vector<uint32_t> a_vec{25, 13};
        std::vector<Plaintext> a_pt_vec;
        auto vec_size = a_vec.size();
        for (size_t i = 0; i < vec_size; i++) {
          Plaintext a;
          a.Set(a_vec[i]);
          a_pt_vec.push_back(a);
        }
        
        std::vector<Plaintext *> a_pt_pts;
        ValueVecToPtsVec(a_pt_vec, a_pt_pts);
        auto a_pt_span = absl::MakeConstSpan(a_pt_pts.data(), vec_size);
        auto a_ct_vec = encryptor_->Encrypt(a_pt_span);
        std::vector<Ciphertext *> a_ct_pts;
        ValueVecToPtsVec(a_ct_vec, a_ct_pts);
        auto a_ct_span = absl::MakeConstSpan(a_ct_pts.data(), vec_size);
        std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(a_ct_span);
    }

  TEST_F(LEICHITest, DISABLE_CTPlusCT) {
      std::vector<int32_t> a_vec{25, 13};
      std::vector<int32_t> b_vec{-25, 13};

      std::vector<Plaintext> a_pt_vec;
      std::vector<Plaintext> b_pt_vec;
      auto vec_size = a_vec.size();

      for (size_t i = 0; i < vec_size; i++) {
          Plaintext a;
          a.Set(a_vec[i]);
          a_pt_vec.push_back(a);

          Plaintext b;
          b.Set(b_vec[i]);
          b_pt_vec.push_back(b);
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
  }

  TEST_F(LEICHITest, DISABLE_CTPlusPT) {
    std::vector<int32_t> a_vec{25, 13, 15};
    std::vector<int32_t> b_vec{-25, 13, 15};

    std::vector<Plaintext> a_pt_vec;
    std::vector<Plaintext> b_pt_vec;
    auto vec_size = a_vec.size();

    for (size_t i = 0; i < vec_size; i++) {
      Plaintext a;
      a.Set(a_vec[i]);
      a_pt_vec.push_back(a);

      Plaintext b;
      b.Set(b_vec[i]);
      b_pt_vec.push_back(b);
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
  }

  TEST_F(LEICHITest, DISABLE_PTPlusCT) {
    std::vector<int32_t> a_vec{25, 13, 15};
    std::vector<int32_t> b_vec{25, 13, 15};

    std::vector<Plaintext> a_pt_vec;
    std::vector<Plaintext> b_pt_vec;
    auto vec_size = a_vec.size();

    for (size_t i = 0; i < vec_size; i++) {
      Plaintext a;
      a.Set(a_vec[i]);
      a_pt_vec.push_back(a);

      Plaintext b;
      b.Set(b_vec[i]);
      b_pt_vec.push_back(b);
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

    std::vector<Ciphertext> res_ct_vec = evaluator_->Add(a_pt_span, b_ct_span);

    std::vector<Ciphertext *> res_ct_pts;
    ValueVecToPtsVec(res_ct_vec, res_ct_pts);
    auto res_ct_span = absl::MakeConstSpan(res_ct_pts.data(), vec_size);
    std::vector<Plaintext> res_pt_vec = decryptor_->Decrypt(res_ct_span);
  }


  TEST_F(LEICHITest, DISABLE_CTSubCT) {
      std::vector<int32_t> a_vec{50, 30};
      std::vector<int32_t> b_vec{-20, 10};
      std::vector<int32_t> expect_res{30, 20};

      std::vector<Plaintext> a_pt_vec;
      std::vector<Plaintext> b_pt_vec;
      auto vec_size = a_vec.size();
      for (size_t i = 0; i < vec_size; i++) {
          Plaintext a;
          a.Set(a_vec[i]);
          a_pt_vec.push_back(a);

          Plaintext b;
          b.Set(b_vec[i]);
          b_pt_vec.push_back(b);
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
  }

  TEST_F(LEICHITest, DISABLE_CTSubPT) {
    std::vector<int32_t> a_vec{25, 13, 15};
    std::vector<int32_t> b_vec{20, 10, 10};

    std::vector<Plaintext> a_pt_vec;
    std::vector<Plaintext> b_pt_vec;
    auto vec_size = a_vec.size();

    for (size_t i = 0; i < vec_size; i++) {
      Plaintext a;
      a.Set(a_vec[i]);
      a_pt_vec.push_back(a);

      Plaintext b;
      b.Set(b_vec[i]);
      b_pt_vec.push_back(b);
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
  } 

  TEST_F(LEICHITest, DISABLE_PTSubCT) {
    std::vector<int32_t> a_vec{25, 13, 15};
    std::vector<int32_t> b_vec{20, 10, 10};

    std::vector<Plaintext> a_pt_vec;
    std::vector<Plaintext> b_pt_vec;
    auto vec_size = a_vec.size();
    for (size_t i = 0; i < vec_size; i++) {
      Plaintext a;
      a.Set(a_vec[i]);
      a_pt_vec.push_back(a);

      Plaintext b;
      b.Set(b_vec[i]);
      b_pt_vec.push_back(b);
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
  }

  TEST_F(LEICHITest, DISABLE_CTMultiplyPT) {
      std::vector<int32_t> a_vec{-5, 3};
      std::vector<int32_t> b_vec{2, 1};
      std::vector<int32_t> expect_res{10, 3};

      std::vector<Plaintext> a_pt_vec;
      std::vector<Plaintext> b_pt_vec;

      for (size_t i = 0; i < a_vec.size(); i++) {
          Plaintext a;
          a.Set(a_vec[i]);
          a_pt_vec.push_back(a);
      }
      for (size_t i = 0; i < b_vec.size(); i++) {
          Plaintext b;
          b.Set(b_vec[i]);
          b_pt_vec.push_back(b);
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
  }
}  // namespace heu::lib::algorithms::leichi_paillier::test
