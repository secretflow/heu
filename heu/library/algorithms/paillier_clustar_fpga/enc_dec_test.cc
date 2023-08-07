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

#include "heu/library/algorithms/paillier_clustar_fpga/vector_encryptor.h"
#include "heu/library/algorithms/paillier_clustar_fpga/vector_decryptor.h"
#include "heu/library/algorithms/paillier_clustar_fpga/vector_evaluator.h"
#include "heu/library/algorithms/paillier_clustar_fpga/key_generator.h"
#include "heu/library/algorithms/paillier_clustar_fpga/utils/facility.h"
#include "gtest/gtest.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/paillier_operators.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"
using heu::lib::algorithms::paillier_clustar_fpga::fpga_engine::CFPGATypes;
using heu::lib::algorithms::paillier_clustar_fpga::fpga_engine::c_malloc_init_zero;
namespace heu::lib::algorithms::paillier_clustar_fpga::test {

class CEncDecTest : public ::testing::TestWithParam<size_t> {
protected:
    void SetUp() override {
        unsigned key_length = GetParam();
        KeyGenerator::Generate(key_length, &sk_, &pk_);
        encryptor_ = std::make_shared<Encryptor>(pk_);
        decryptor_ = std::make_shared<Decryptor>(pk_, sk_);
        evaluator_ = std::make_shared<Evaluator>(pk_);
        key_conf_  = std::make_shared<fpga_engine::CKeyLenConfig>(key_length);
    }

protected:
    SecretKey sk_;
    PublicKey pk_;
    std::shared_ptr<Encryptor> encryptor_;
    std::shared_ptr<Decryptor> decryptor_;
    std::shared_ptr<Evaluator> evaluator_;
    std::shared_ptr<fpga_engine::CKeyLenConfig> key_conf_;
};

INSTANTIATE_TEST_SUITE_P(SubTest, CEncDecTest,
                         ::testing::Values(1024));

TEST_P(CEncDecTest, EncodeDecode) {
    // Prepare
    std::vector<int32_t> a_vec{-234, 890, -567, 0, -10, -20, 1000};
    std::vector<int32_t> expect_res{-234, 890, -567, 0, -10, -20, 1000};
    std::vector<Plaintext> a_plain_vec;
    auto vec_size = a_vec.size();
    for (size_t i = 0; i < vec_size; i++) {
        a_plain_vec.push_back(Plaintext(a_vec[i]));
    }

    // Encode
    std::vector<Plaintext*> a_plain_ptrs;
    CMonoFacility::ValueVecToPtrVec(a_plain_vec, a_plain_ptrs);
    auto a_plain_span = absl::MakeConstSpan(a_plain_ptrs.data(), vec_size);
    auto lambda_deleter = [](char *ptr) {
        free(ptr);
    };
    size_t pts_size = a_plain_span.size();
    std::shared_ptr<char> res_fpn(fpga_engine::c_malloc_init_zero(key_conf_->plain_byte_ * pts_size), lambda_deleter);
    std::shared_ptr<char> res_base_fpn(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size), lambda_deleter);
    std::shared_ptr<char> res_exp_fpn(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size), lambda_deleter);
    encryptor_->Encode(a_plain_span, res_fpn, res_base_fpn, res_exp_fpn);

    // Decode
    std::vector<Plaintext> res_plain_vec = decryptor_->Decode(res_fpn, res_base_fpn, res_exp_fpn, pts_size);

    // Compare
    for (size_t i = 0; i < vec_size; i++) {
        // std::cout<<"res_plain_vec["<<i<<"]: "<<res_plain_vec[i].Get<int64_t>()<<std::endl;
        EXPECT_EQ(res_plain_vec[i], Plaintext(expect_res[i]));
    }
}

TEST_P(CEncDecTest, EncryptDecrypt) {
    // Prepare
    std::vector<int32_t> a_vec{-234, 890, -567, 0, -1, 10001};
    std::vector<int32_t> expect_res{-234, 890, -567, 0, -1, 10001};
        
    std::vector<Plaintext> a_plain_vec;
    auto vec_size = a_vec.size();
    for (size_t i = 0; i < vec_size; i++) {
        a_plain_vec.push_back(Plaintext(a_vec[i]));
    }

    // Encrypt
    std::vector<Plaintext*> a_plain_ptrs;
    CMonoFacility::ValueVecToPtrVec(a_plain_vec, a_plain_ptrs);
    auto a_plain_span = absl::MakeConstSpan(a_plain_ptrs.data(), vec_size);
    auto a_cipher_vec = encryptor_->Encrypt(a_plain_span);
    // for (size_t i = 0; i < a_cipher_vec.size(); i++) {
    //     const Ciphertext& cur_cipher = a_cipher_vec[i];
    //     std::string cur_str = cur_cipher.ToString();
    //     std::cout<<"cipher_str: "<<cur_str<<std::endl;
    // }

    // Decrypt
    std::vector<Ciphertext*> a_cipher_ptrs;
    CMonoFacility::ValueVecToPtrVec(a_cipher_vec, a_cipher_ptrs);
    auto a_cipher_span = absl::MakeConstSpan(a_cipher_ptrs.data(), vec_size);
    std::vector<Plaintext> res_plain_vec = decryptor_->Decrypt(a_cipher_span);

    // Compare
    for (size_t i = 0; i < vec_size; i++) {
        // std::cout<<"res_plain_vec["<<i<<"]: "<<res_plain_vec[i].Get<int64_t>()<<std::endl;
        EXPECT_EQ(res_plain_vec[i], Plaintext(expect_res[i]));
    }
}

TEST_P(CEncDecTest, EncryptZero) {
    // Step 1 encrpyt
    size_t num = 30;
    std::vector<Ciphertext> enc_zeros = encryptor_->EncryptZero(num);

    // Step 2 decrypt
    std::vector<Ciphertext*> enc_zeros_ptrs;
    CMonoFacility::ValueVecToPtrVec(enc_zeros, enc_zeros_ptrs);
    EXPECT_EQ(num, enc_zeros_ptrs.size());
    auto enc_zeros_span = absl::MakeConstSpan(enc_zeros_ptrs.data(), enc_zeros_ptrs.size());
    
    std::vector<Plaintext> dec_zeros;
    dec_zeros.resize(num);
    std::vector<Plaintext*> dec_zeros_ptrs;
    CMonoFacility::ValueVecToPtrVec(dec_zeros, dec_zeros_ptrs);
    auto dec_zeros_span = absl::MakeSpan(dec_zeros_ptrs.data(), dec_zeros_ptrs.size());
    decryptor_->Decrypt(enc_zeros_span, dec_zeros_span);

    // Step 3 check
    int zero = 0;
    Plaintext expect_zero(zero);
    for (size_t i = 0; i < dec_zeros.size(); i++) {
        EXPECT_EQ(dec_zeros[i], expect_zero);
    }
}

TEST_P(CEncDecTest, EncryptDecryptWithoutObf) {
    // Prepare
    std::vector<int32_t> a_vec{-234, 890, -567, 0, -1, 10001};
    std::vector<int32_t> expect_res{-234, 890, -567, 0, -1, 10001};
        
    std::vector<Plaintext> a_plain_vec;
    auto vec_size = a_vec.size();
    for (size_t i = 0; i < vec_size; i++) {
        a_plain_vec.push_back(Plaintext(a_vec[i]));
    }

    // Encrypt
    std::vector<Plaintext*> a_plain_ptrs;
    CMonoFacility::ValueVecToPtrVec(a_plain_vec, a_plain_ptrs);
    auto a_plain_span = absl::MakeConstSpan(a_plain_ptrs.data(), vec_size);
    auto a_cipher_vec = encryptor_->EncryptWithoutObf(a_plain_span);
    // for (size_t i = 0; i < a_cipher_vec.size(); i++) {
    //     const Ciphertext& cur_cipher = a_cipher_vec[i];
    //     std::string cur_str = cur_cipher.ToString();
    //     std::cout<<"cipher_str: "<<cur_str<<std::endl;
    // }

    // Decrypt
    std::vector<Ciphertext*> a_cipher_ptrs;
    CMonoFacility::ValueVecToPtrVec(a_cipher_vec, a_cipher_ptrs);
    auto a_cipher_span = absl::MakeConstSpan(a_cipher_ptrs.data(), vec_size);
    std::vector<Plaintext> res_plain_vec = decryptor_->Decrypt(a_cipher_span);

    // Compare
    for (size_t i = 0; i < vec_size; i++) {
        // std::cout<<"res_plain_vec["<<i<<"]: "<<res_plain_vec[i].Get<int64_t>()<<std::endl;
        EXPECT_EQ(res_plain_vec[i], Plaintext(expect_res[i]));
    }
}

TEST_P(CEncDecTest, EncryptWithAudit) {
    // Prepare
    std::vector<int32_t> a_vec{-234, 890, -567, 0, -1, 10001};
    std::vector<int32_t> expect_res{-234, 890, -567, 0, -1, 10001};
        
    std::vector<Plaintext> a_plain_vec;
    auto vec_size = a_vec.size();
    for (size_t i = 0; i < vec_size; i++) {
        a_plain_vec.push_back(Plaintext(a_vec[i]));
    }

    // Encrypt
    std::vector<Plaintext*> a_plain_ptrs;
    CMonoFacility::ValueVecToPtrVec(a_plain_vec, a_plain_ptrs);
    auto a_plain_span = absl::MakeConstSpan(a_plain_ptrs.data(), vec_size);
    auto a_cipher_pair = encryptor_->EncryptWithAudit(a_plain_span);
    auto a_cipher_vec = a_cipher_pair.first;
    // for (size_t i = 0; i < a_cipher_vec.size(); i++) {
    //     const Ciphertext& cur_cipher = a_cipher_vec[i];
    //     std::string cur_str = cur_cipher.ToString();
    //     std::cout<<i<<"th cipher_str: "<<cur_str<<std::endl;
    // }
    
    auto cipher_audit = a_cipher_pair.second;
    EXPECT_EQ(a_cipher_vec.size(), cipher_audit.size());
    // for (size_t i = 0; i < cipher_audit.size(); i++) {
    //     std::cout<<i<<" th audit: "<<cipher_audit[i]<<std::endl;
    // }

    // Decrypt
    std::vector<Ciphertext*> a_cipher_ptrs;
    CMonoFacility::ValueVecToPtrVec(a_cipher_vec, a_cipher_ptrs);
    auto a_cipher_span = absl::MakeConstSpan(a_cipher_ptrs.data(), vec_size);
    std::vector<Plaintext> res_plain_vec = decryptor_->Decrypt(a_cipher_span);

    // Compare
    for (size_t i = 0; i < vec_size; i++) {
        // std::cout<<"res_plain_vec["<<i<<"]: "<<res_plain_vec[i].Get<int64_t>()<<std::endl;
        EXPECT_EQ(res_plain_vec[i], Plaintext(expect_res[i]));
    }
}

TEST_P(CEncDecTest, EncryptMaxNum) {
    // Prepare
    uint64_t overflow_val = static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 10;
    std::vector<uint64_t> a_vec{234, 890, overflow_val, 0, overflow_val - 1, 10001};
    std::vector<Plaintext> a_plain_vec;
    auto vec_size = a_vec.size();
    for (size_t i = 0; i < vec_size; i++) {
        a_plain_vec.push_back(Plaintext(a_vec[i]));
    }

    // Encrypt
    std::vector<Plaintext*> a_plain_ptrs;
    CMonoFacility::ValueVecToPtrVec(a_plain_vec, a_plain_ptrs);
    auto a_plain_span = absl::MakeConstSpan(a_plain_ptrs.data(), vec_size);
    EXPECT_THROW(encryptor_->Encrypt(a_plain_span), std::exception); 
}

} // heu::lib::algorithms::paillier_clustar_fpga::test
