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

#pragma once

#include <stdint.h>

#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/config/config.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

void init_params();

void raise_error(const char* error_info);

void check_error_status(int rc);

char* c_malloc_init_zero(size_t byte_length);

void cpu_invert_pen_mul_fpn(void* th_para);

void fpn_matrix_elementwise_multiply_pen_matrix(
    char* fpn_encode, void* fpn_base_void, void* fpn_exp_void, char* pen_cipher,
    void* pen_base_void, void* pen_exp_void, char* res_cipher,
    void* res_base_void, void* res_exp_void, size_t fpn_dim0, size_t fpn_dim1,
    size_t pen_dim0, size_t pen_dim1, char* n, char* g, char* nsquare,
    char* max_int, size_t encode_bitlength, size_t cipher_bitlength,
    size_t device_num);

void encrypt_without_obf(char* fpn_encode, void* fpn_base_void,
                         void* fpn_exp_void, char* res_cipher,
                         void* res_base_void, void* res_exp_void, char* n,
                         char* g, char* nsquare, char* max_int,
                         size_t encode_bitlength, size_t cipher_bitlength,
                         size_t vector_size, size_t device_num);

void obf_modular_exponentiation(char* randoms, size_t random_bitlength, char* n,
                                char* g, char* nsquare, char* max_int,
                                char* res, size_t res_bitlength,
                                size_t vector_size, size_t device_num);

void obf_modular_multiplication(char* pen_cipher, void* pen_base_void,
                                void* pen_exp_void, char* obf_seeds,
                                char* res_cipher, void* res_base_void,
                                void* res_exp_void, char* n, char* g,
                                char* nsquare, char* max_int,
                                size_t cipher_bitlength, size_t res_bitlength,
                                size_t vector_size, size_t device_num);

void decrypt(char* pen_cipher, void* pen_base_void, void* pen_exp_void,
             char* res_encode, void* res_base_void, void* res_exp_void, char* n,
             char* g, char* nsquare, char* max_int, char* p, char* q,
             char* psquare, char* qsquare, char* q_inverse, char* hp, char* hq,
             size_t encode_bitlength, size_t cipher_bitlength,
             size_t vector_size, size_t device_num);

void cpu_encode_int(void* th_para);

void encode_int(void* ints_void, char* res_encode, void* res_base_void,
                void* res_exp_void, int32_t precision, char* n, char* max_int,
                size_t encode_bitlength, size_t vector_size, size_t device_num);

void cpu_decode_int(void* th_para);

void decode_int(char* numbers_encode, void* numbers_base_void,
                void* numbers_exp_void, char* n, char* max_int,
                size_t encode_bitlength, void* res_void, size_t vector_size);

void mpint_random(char* res, size_t plain_bitlength, size_t vec_size,
                  char* max_num);

void pen_add_with_same_exp(char* pen1_cipher, void* pen1_base_void,
                           void* pen1_exp_void, char* pen2_cipher,
                           void* pen2_base_void, void* pen2_exp_void,
                           char* res_cipher, void* res_base_void,
                           void* res_exp_void, size_t pen1_dim0,
                           size_t pen1_dim1, size_t pen2_dim0, size_t pen2_dim1,
                           char* nsquare, size_t cipher_bitlength,
                           size_t device_num);

void pen_sum_with_same_exp(char* pen_cipher, void* pen_base_void,
                           void* pen_exp_void, char* res_cipher,
                           void* res_base_void, void* res_exp_void,
                           size_t pen_dim0, size_t pen_dim1, char* n, char* g,
                           char* nsquare, char* max_int,
                           size_t cipher_bitlength, size_t device_num);
}  // namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
