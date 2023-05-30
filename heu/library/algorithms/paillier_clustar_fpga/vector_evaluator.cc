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

#include "heu/library/algorithms/paillier_clustar_fpga/vector_evaluator.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/paillier_operators.h"
#include "heu/library/algorithms/paillier_clustar_fpga/utils/facility.h"
#include <sstream>
#include<iomanip>
#include <chrono> 
namespace heu::lib::algorithms::paillier_clustar_fpga {

using fpga_engine::CFPGATypes;

Evaluator::Evaluator(const PublicKey& pk) : 
pub_key_(pk), 
encryptor_(pub_key_), 
pub_key_helper_(&pub_key_),
key_conf_(pub_key_.GetN().BitCount())
{
    pub_key_helper_.TransformToBytes();
}

// Cipher + Cipher(0)
void Evaluator::Randomize(Span<Ciphertext> ct) const {
    size_t ct_size = ct.size();
    std::vector<Ciphertext> zero_ciphers = encryptor_.EncryptZero(ct_size);
    std::vector<Ciphertext*> zero_ciphers_ptr;
    zero_ciphers_ptr.reserve(ct_size);
    CMonoFacility::ValueVecToPtrVec(zero_ciphers, zero_ciphers_ptr);
    ConstSpan<Ciphertext> zero_ciphers_span = absl::MakeConstSpan(zero_ciphers_ptr.data(), zero_ciphers_ptr.size());
    AddInplace(ct, zero_ciphers_span);
}

// Use pen_add_with_same_exp instead of pen_matrix_add_pen_matrix to calc int only
std::vector<Ciphertext> Evaluator::Add(ConstSpan<Ciphertext> a, ConstSpan<Ciphertext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "Cipher + Cipher error: size mismatch");
    size_t elem_size = a.size();

    // Part 1 data prepare
    auto lambda_deleter = [](char *ptr) {
        free(ptr);
    };

    // 1-1 prepare left
    std::shared_ptr<char> left_pen(fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * elem_size), lambda_deleter);
    std::shared_ptr<char> left_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    std::shared_ptr<char> left_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    CMonoFacility::CipherHeuToFpga(a, key_conf_.cipher_byte_, left_pen, left_base, left_exp);

    // 1-2 prepare right
    std::shared_ptr<char> right_pen(fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * elem_size), lambda_deleter);
    std::shared_ptr<char> right_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    std::shared_ptr<char> right_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    CMonoFacility::CipherHeuToFpga(b, key_conf_.cipher_byte_, right_pen, right_base, right_exp);

    // 1-3 prepare result
    std::shared_ptr<char> res_pen(fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * elem_size), lambda_deleter);
    std::shared_ptr<char> res_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    std::shared_ptr<char> res_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    
    // Part 2 add
    size_t left_row = 1;
    size_t left_col = a.size();
    size_t right_row = 1;
    size_t right_col = b.size();
    char *pub_n_square = pub_key_helper_.GetBytesNSquare();
    size_t fpga_dev_num = 0; // no effect
    fpga_engine::pen_add_with_same_exp(left_pen.get(),  left_base.get(),  left_exp.get(),
                                       right_pen.get(), right_base.get(), right_exp.get(),
                                       res_pen.get(),   res_base.get(),   res_exp.get(),
                                       left_row, left_col, right_row,    right_col,
                                       pub_n_square, key_conf_.cipher_bits_, fpga_dev_num);

    // release memory in time: left and right data
    left_pen.reset();
    left_base.reset();
    left_exp.reset();
    right_pen.reset();
    right_base.reset();
    right_exp.reset();

    // Part 3 trasform data back to heu
    std::vector<Ciphertext> res_vec;
    res_vec.reserve(elem_size);
    CMonoFacility::CipherFpgaToHeu(res_pen, res_exp, elem_size, key_conf_.cipher_byte_, res_vec);
    
    return res_vec;
}

// Use pen_add_with_same_exp instead of pen_matrix_add_pen_matrix to calc int only
std::vector<Ciphertext> Evaluator::Add(ConstSpan<Ciphertext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "Cipher + Plain error: size mismatch");
    size_t elem_size = a.size();
    
    // Step 1 data preparation
    // 1-1 prepare cipher
    auto lambda_deleter = [](char *ptr) {
        free(ptr);
    };

    std::shared_ptr<char> left_pen(fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * elem_size), lambda_deleter);
    std::shared_ptr<char> left_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    std::shared_ptr<char> left_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    CMonoFacility::CipherHeuToFpga(a, key_conf_.cipher_byte_, left_pen, left_base, left_exp);

    // 1-2 encrypt plain
    std::vector<Ciphertext> right_cipher = encryptor_.EncryptWithoutObf(b);
    std::shared_ptr<char> right_pen(fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * elem_size), lambda_deleter);
    std::shared_ptr<char> right_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    std::shared_ptr<char> right_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    CMonoFacility::CipherVecToFpga(right_cipher, key_conf_.cipher_byte_, right_pen, right_base, right_exp);

    // 1-3 prepare result
    std::shared_ptr<char> res_pen(fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * elem_size), lambda_deleter);
    std::shared_ptr<char> res_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    std::shared_ptr<char> res_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);

    // Step 2 Add
    size_t left_row = 1;
    size_t left_col = a.size();
    size_t right_row = 1;
    size_t right_col = b.size();
    char *pub_n_square = pub_key_helper_.GetBytesNSquare();
    size_t fpga_dev_num = 0; // no effect
    fpga_engine::pen_add_with_same_exp(left_pen.get(),  left_base.get(),  left_exp.get(),
                                       right_pen.get(), right_base.get(), right_exp.get(),
                                       res_pen.get(),   res_base.get(),   res_exp.get(),
                                       left_row, left_col, right_row, right_col,
                                       pub_n_square, key_conf_.cipher_bits_, fpga_dev_num);

    // release memory in time: left and right cipher
    left_pen.reset();
    left_base.reset();
    left_exp.reset();
    right_pen.reset();
    right_base.reset();
    right_exp.reset();

    // Step 3 trasform data back to heu
    std::vector<Ciphertext> res_vec;
    res_vec.reserve(elem_size);
    CMonoFacility::CipherFpgaToHeu(res_pen, res_exp, elem_size, key_conf_.cipher_byte_, res_vec);

    return res_vec;
}
                     
std::vector<Ciphertext> Evaluator::Add(ConstSpan<Plaintext> a, ConstSpan<Ciphertext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "Plain + Cipher error: size mismatch");
    return Add(b, a);
}

// TODO: use thread to speed up
std::vector<Plaintext> Evaluator::Add(ConstSpan<Plaintext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "Plain + Plain error: size mismatch");
    size_t elem_size = a.size();
    std::vector<Plaintext> res_vec;
    res_vec.reserve(elem_size);
    for (size_t i = 0; i < elem_size; i++) {
        Plaintext res = *a[i] + *b[i];
        res_vec.emplace_back(std::move(res));
    }

    return res_vec;
}

void Evaluator::AddInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "AddInplace Cipher + Cipher error: size mismatch");
    size_t elem_size = a.size();
    auto result = Add(a, b);
    for (size_t i = 0; i < elem_size; i++) {
        *a[i] = std::move(result[i]);
    }
}

void Evaluator::AddInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "AddInplace Cipher + Plain error: size mismatch");
    size_t elem_size = a.size();
    auto result = Add(a, b);
    for (size_t i = 0; i < elem_size; i++) {
        *a[i] = std::move(result[i]);
    }
}

void Evaluator::AddInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "AddInplace Plain + Plain error: size mismatch");
    size_t elem_size = a.size();
    auto result = Add(a, b);
    for (size_t i = 0; i < elem_size; i++) {
        *a[i] = std::move(result[i]);
    }
}

std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Ciphertext> a, ConstSpan<Ciphertext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "Cipher - Cipher error: size mismatch");
    size_t elem_size = a.size();

    std::vector<Ciphertext> neg_b_vec = Negate(b);
    std::vector<Ciphertext*> neg_b_ptr;
    neg_b_ptr.reserve(elem_size);
    CMonoFacility::ValueVecToPtrVec(neg_b_vec, neg_b_ptr);
    ConstSpan<Ciphertext> neg_b_span = absl::MakeConstSpan(neg_b_ptr.data(), neg_b_ptr.size());
    return Add(a, neg_b_span);
}

std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Ciphertext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "Cipher - Plain error: size mismatch");
    size_t elem_size = a.size();

    std::vector<Plaintext> neg_b_vec;
    neg_b_vec.reserve(elem_size);
    for (auto item : b) {
        neg_b_vec.push_back(-(*item));
    }

    std::vector<Plaintext*> neg_b_ptr;
    neg_b_ptr.reserve(elem_size);
    CMonoFacility::ValueVecToPtrVec(neg_b_vec, neg_b_ptr);
    ConstSpan<Plaintext> neg_b_span = absl::MakeConstSpan(neg_b_ptr.data(), neg_b_ptr.size());
    return Add(a, neg_b_span);
}

std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Plaintext> a, ConstSpan<Ciphertext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "Plain - Cipher error: size mismatch");
    size_t elem_size = a.size();

    std::vector<Ciphertext> neg_b_vec = Negate(b);
    std::vector<Ciphertext*> neg_b_ptr;
    neg_b_ptr.reserve(elem_size);
    CMonoFacility::ValueVecToPtrVec(neg_b_vec, neg_b_ptr); 
    ConstSpan<Ciphertext> neg_b_span = absl::MakeConstSpan(neg_b_ptr.data(), neg_b_ptr.size());
    return Add(a, neg_b_span);
}

// TODO: use threads to speed up
std::vector<Plaintext> Evaluator::Sub(ConstSpan<Plaintext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "Plain - Plain error: size mismatch");
    size_t elem_size = a.size();

    std::vector<Plaintext> result;
    result.reserve(elem_size);
    for (size_t i = 0; i < elem_size; i++) {
        Plaintext res = *a[i] - *b[i];
        result.emplace_back(std::move(res));
    }

    return result;
}

void Evaluator::SubInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "SubInplace Cipher - Cipher error: size mismatch");
    auto res = Sub(a, b);
    size_t vec_size = res.size();
    for (size_t i = 0; i < vec_size; i++) {
        *a[i] = res[i];
    }
}

void Evaluator::SubInplace(Span<Ciphertext> a, ConstSpan<Plaintext> p) const {
    YACL_ENFORCE(a.size() == p.size(), "SubInplace Cipher - Plain error: size mismatch");
    auto res = Sub(a, p);
    size_t vec_size = res.size();
    for (size_t i = 0; i < vec_size; i++) {
        *a[i] = res[i];
    }
}

void Evaluator::SubInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE(a.size() == b.size(), "SubInplace Plain - Plain error: size mismatch");
    auto res = Sub(a, b);
    size_t vec_size = res.size();
    for (size_t i = 0; i < vec_size; i++) {
        *a[i] = res[i];
    }
}

// 1 plain -> encode
// 2 fpga calc fpn elementwise multi pen
std::vector<Ciphertext> Evaluator::Mul(ConstSpan<Ciphertext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE((a.size() == b.size()) || (a.size() == 1) || (b.size() == 1), "Cipher * Plain error: size mismatch");
    
    // Step 1 data prepration
    // 1-1 data format for cipher
    auto lambda_deleter = [](char *ptr) {
        free(ptr);
    };
    size_t a_size = a.size();
    std::shared_ptr<char> cipher_pen(fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * a_size), lambda_deleter);
    std::shared_ptr<char> cipher_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * a_size), lambda_deleter);
    std::shared_ptr<char> cipher_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * a_size), lambda_deleter);
    CMonoFacility::CipherHeuToFpga(a, key_conf_.cipher_byte_, cipher_pen, cipher_base, cipher_exp);

    // 1-2 encode for plain
    size_t b_size = b.size();
    std::shared_ptr<int64_t[]> pt_arr(new int64_t[b_size]);
    CMonoFacility::PlainHeuToFpga(b, pt_arr);
    std::shared_ptr<char> pt_fpn(fpga_engine::c_malloc_init_zero(key_conf_.plain_byte_ * b_size), lambda_deleter);
    std::shared_ptr<char> pt_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * b_size), lambda_deleter);
    std::shared_ptr<char> pt_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * b_size), lambda_deleter);
    char *pub_key_n = pub_key_helper_.GetBytesN();
    CMonoFacility::FpgaEncode(pub_key_n, b_size, key_conf_.plain_bits_, pt_arr, pt_fpn, pt_base, pt_exp);
    
    // release memory in time: transformed input data
    pt_arr.reset();

    // 1-3 result data
    size_t res_size = a_size > b_size ? a_size : b_size;
    std::shared_ptr<char> res_pen(fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * res_size), lambda_deleter);
    std::shared_ptr<char> res_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * res_size), lambda_deleter);
    std::shared_ptr<char> res_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * res_size), lambda_deleter);

    // Step 2 fpga calc
    char *pub_key_n_square = pub_key_helper_.GetBytesNSquare();
    char *pub_key_max_int = pub_key_helper_.GetBytesMaxInt();
    size_t fpga_dev_num = 0; // no effect
    fpga_engine::fpn_matrix_elementwise_multiply_pen_matrix(
        pt_fpn.get(), pt_base.get(), pt_exp.get(),
        cipher_pen.get(), cipher_base.get(), cipher_exp.get(),
        res_pen.get(), res_base.get(), res_exp.get(),
        1, b_size, 1, a_size,
        pub_key_n, nullptr, pub_key_n_square, pub_key_max_int,
        key_conf_.plain_bits_, key_conf_.cipher_bits_, fpga_dev_num);

    // Step 3 format results back to heu
    std::vector<Ciphertext> res_vec;
    res_vec.reserve(res_size);
    CMonoFacility::CipherFpgaToHeu(res_pen, res_exp, res_size, key_conf_.cipher_byte_, res_vec);

    return res_vec;
}
                    
std::vector<Ciphertext> Evaluator::Mul(ConstSpan<Plaintext> a, ConstSpan<Ciphertext> b) const {
    YACL_ENFORCE((a.size() == b.size()) || (a.size() == 1) || (b.size() == 1), "Plain * Cipher error: size mismatch");
    return Mul(b, a);
}

// Calc in CPU directly
std::vector<Plaintext> Evaluator::Mul(ConstSpan<Plaintext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE((a.size() == b.size() && a.size() != 0) 
                 || (a.size() == 1 && b.size() != 0) 
                 || (b.size() == 1 && a.size() != 0), 
                 "Plain * Plain error: size mismatch");

    size_t a_size = a.size();
    size_t b_size = b.size();
    size_t vec_size = a_size >= b_size ? a_size : b_size;
    std::vector<Plaintext> plain_vec;
    plain_vec.reserve(vec_size);
    
    if (a_size == 1) {
        // case 1: a_size == 1
        const Plaintext *a_val = a[0];
        for (size_t i = 0; i < b_size; i++) {
            Plaintext mul_res = (*a_val) * (*b[i]);
            plain_vec.emplace_back(std::move(mul_res));
        }
    } else if (b_size == 1) {
        // case 2: b_size == 1
        const Plaintext *b_val = b[0];
        for (size_t i = 0; i < a_size; i++) {
            Plaintext mul_res = (*a[i]) * (*b_val);
            plain_vec.emplace_back(std::move(mul_res));
        }
    } else if (a_size == b_size) {
        // case 3: a_size == b_size
        for (size_t i = 0; i < a_size; i++) {
            Plaintext mul_res = (*a[i]) * (*b[i]);
            plain_vec.emplace_back(std::move(mul_res));
        }
    }  

    return plain_vec;
}
                            
// Notice: input parameter size requirement is NOT the same as Mul
void Evaluator::MulInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE((a.size() == b.size()) || (b.size() == 1), "MulInplace Cipher * Plain error: size mismatch");
    auto result = Mul(a, b);
    size_t res_size = result.size(); // res_size supposed to == a.size()
    for (size_t i = 0; i < res_size; i++) {
        *a[i] = std::move(result[i]);
    }
}

// Notice: input parameter size requirement is NOT the same as Mul
void Evaluator::MulInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const {
    YACL_ENFORCE((a.size() == b.size()) || (b.size() == 1), "MulInplace Plain * Plain error: size mismatch");
    auto result = Mul(a, b);
    size_t res_size = result.size(); // res_size supposed to == a.size()
    for (size_t i = 0; i < res_size; i++) {
        *a[i] == std::move(result[i]);
    }
}

// cipher * cipher(-1)
std::vector<Ciphertext> Evaluator::Negate(ConstSpan<Ciphertext> a) const {
    int64_t zero_val = -1;
    Plaintext neg_one(zero_val);
    std::vector<Plaintext*> neg_one_ptr;
    neg_one_ptr.emplace_back(&neg_one);
    ConstSpan<Plaintext> neg_one_span = absl::MakeConstSpan(neg_one_ptr.data(), 1);
    
    std::vector<Ciphertext> result = Mul(a, neg_one_span);
    return result;
}

void Evaluator::NegateInplace(Span<Ciphertext> a) const {
    auto neg_a = Negate(a);
    size_t vec_size = neg_a.size();
    for (size_t i = 0; i < vec_size; i++) {
        *a[i] = std::move(neg_a[i]);
    }
}

void Evaluator::CalcSum(Ciphertext* sum, ConstSpan<Ciphertext> input) const {
    YACL_ENFORCE((input.size() > 0) && (sum != nullptr), "CalcSum error: input size is 0");
    size_t elem_size = input.size();

    // Part 1 data prepare
    auto lambda_deleter = [](char *ptr) {
        free(ptr);
    };

    // 1-1 prepare input
    std::shared_ptr<char> src_pen(fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * elem_size), lambda_deleter);
    std::shared_ptr<char> src_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    std::shared_ptr<char> src_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * elem_size), lambda_deleter);
    CMonoFacility::CipherHeuToFpga(input, key_conf_.cipher_byte_, src_pen, src_base, src_exp);

    // 1-2 prepare result
    std::shared_ptr<char> res_pen(fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_), lambda_deleter);
    std::shared_ptr<char> res_base(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE), lambda_deleter);
    std::shared_ptr<char> res_exp(fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE), lambda_deleter);

    // Part 2 sum the ciphers in input
    char *pub_n_square = pub_key_helper_.GetBytesNSquare();
    size_t fpga_dev_num = 0; // no effect
    fpga_engine::pen_sum_with_same_exp(src_pen.get(), src_base.get(), src_exp.get(),
                                       res_pen.get(), res_base.get(), res_exp.get(),
                                       1, elem_size,
                                       nullptr, nullptr, pub_n_square, nullptr,
                                       key_conf_.cipher_bits_, fpga_dev_num);
    // release memory in time: src data
    src_pen.reset();
    src_base.reset();
    src_exp.reset();

    // Part 3 Trasform data back to heu
    Ciphertext sum_cipher(key_conf_.cipher_byte_);
    memcpy(sum_cipher.GetMantissa(), res_pen.get(), key_conf_.cipher_byte_);
    int sum_exp = 0;
    memcpy(&sum_exp, res_exp.get(), CFPGATypes::U_INT32_BYTE);
    sum_cipher.SetExp(sum_exp);

    *sum = std::move(sum_cipher);
}

void Evaluator::CalcSum(Plaintext* sum, ConstSpan<Plaintext> input) const {
    YACL_ENFORCE((input.size() > 0) && (sum != nullptr), "CalcSum error: input size is 0");

    Plaintext loc_sum;
    int64_t zero_num = 0;
    loc_sum.Set(zero_num);
    for (const auto& item : input) {
        loc_sum += *item;
    }
    *sum = std::move(loc_sum);
}

} // heu::lib::algorithms::paillier_clustar_fpga
