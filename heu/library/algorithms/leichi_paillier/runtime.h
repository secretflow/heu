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

#pragma once
#include "openssl/bn.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "heu/library/algorithms/leichi_paillier/pcie/pcie.h"
#include <cstdint>
#include <iostream>
#include <vector>
#include <cmath>
#include "heu/library/algorithms/leichi_paillier/compiler/compiler.h"
#include <stdio.h>
#include <unordered_map>
#include <sstream>

namespace heu::lib::algorithms::leichi_paillier {
    #define BYTECOUNT(x)                ((x)>>3) 
    #define FPGA_SEND_BASE_ADDR         0x24000
    #define NUMBER_OF_PE                 16
    #pragma pack(1)
    enum DEV_STATE{
        OK = 0x00,
        Failed = 0x01,
        Invaled_Dat = 0x02,
        Invaled_Param = 0x03,
        Write_Faild = 0x04,
        Read_Faild = 0x05, 
        Time_out = 0x06 
    }; 
    enum OPERATION_TYPE{
        NONE = 0,
        MONT = 1,
        MONT_CONST = 2,
        MOD_MUL = 3,
        MOD_MUL_CONST = 4,
        MOD_EXP = 5,
        MOD_EXP_CONST_A = 6,
        MOD_EXP_CONST_E = 7,
        MOD_INV_CONST_P = 8,
        MOD_ADD = 9,
        MOD_ADD_CONST = 10,
        // SRAM_DATA_SHIFT = 11,
        PAILLIER_ENC = 12,
        MOD_INV = 13
    };

    struct _public_key{
        int n_bitcount;
        std::vector<uint8_t> g;
        std::vector<uint8_t> n;
    };

    struct _private_key{
        int n_bitcount;
        std::vector<uint8_t> p;
        std::vector<uint8_t> q;
    };

    struct _paillier_key{
        _public_key public_key;
        _private_key private_key;
    };

    struct executor
    {
        std::vector<uint8_t> data_in;
        std::vector<uint8_t> data_out;
        std::vector<uint8_t> inst;
        std::vector<uint8_t> inst_fpga;
        uint32_t in_para_address;
        uint32_t inst_address;
        uint32_t out_address;
        uint32_t out_length;
    };
    #pragma pack()
    class Runtime  {
        public:
            Runtime() = default;
            bool dev_connect();
            bool dev_close();
            bool dev_reset();
            DEV_STATE paillier_encrypt(uint8_t *m,uint8_t *r,std::vector<uint8_t> m_flg,uint32_t vec_size,struct _public_key public_key,uint8_t *output,uint32_t &output_len);
            DEV_STATE paillier_decrypt(uint8_t *ct,uint32_t vec_size,struct _private_key private_key,uint8_t *m_output,uint8_t *m_output_flg);
            DEV_STATE paillier_add(uint8_t *ct1,uint32_t ct1_len,uint8_t *ct2 ,uint32_t ct2_len,uint32_t vec_size,uint8_t *ct_output,uint32_t &output_len,struct _public_key public_key);
            DEV_STATE paillier_mul(uint8_t *ct1,uint32_t ct1_len,uint8_t *m,uint32_t m_size,uint32_t vec_size,uint8_t *ct_output,uint32_t &output_len,struct _public_key public_key);
            DEV_STATE paillier_sub(uint8_t *ct1,uint32_t ct1_len,uint8_t *ct2,uint32_t ct2_len,uint32_t vec_size,uint8_t *ct_output,uint32_t &output_len,struct _public_key public_key);
        private:
            CPcieComm pPcie;
            Compiler compiler;
            void data_inverse(uint8_t* data,uint32_t len);
            void char_array_to_vector(std::vector<uint8_t> &vec,unsigned char* buff,uint32_t buff_size);
            void vector_to_char_array(std::vector<uint8_t>& vec, unsigned char* &arr) ;
            void gen_mont_para(BIGNUM *p, uint32_t p_bitcount,uint8_t*output,uint32_t &len);
            void gen_p_mont_para(BIGNUM *p, uint32_t p_bitcount,uint8_t*output,uint32_t &len,uint8_t flg);

            int  gen_param(uint32_t kernels, uint32_t p_bitcount, uint32_t case_v, uint32_t e_bitcount, uint32_t bool_ele_r_square, uint32_t bits);
            OPERATION_TYPE operation_trans(std::string operation);

            size_t dev_write_reg(size_t in_data, size_t addr);
            size_t dev_read_reg(size_t *out_data, size_t addr);
            size_t dev_write_ddr(uint8_t *in_data, size_t write_len, size_t addr);
            size_t dev_read_ddr(uint8_t *out_data, size_t read_len, size_t addr);
            size_t dev_write_init(uint8_t *in_data, size_t write_len, size_t addr);
            size_t dev_read_init(uint8_t *out_data, size_t read_len, size_t addr);
            void api_set_inst_length(size_t len) ;
            size_t dev_reset_device();
            size_t api_write_inst(uint8_t *inst, size_t write_len,size_t addr);
            size_t api_set_inst_length_clear();
            size_t check_inst_pointer(size_t *out_data);

            int get_p_bitcount_chip(uint32_t p_bitcount);
            void big_sub_const_b(uint8_t* input_a, uint8_t* input_b, uint8_t * output, const uint32_t length, const int p_bitcount, const int p_bitcount_const);
            void big_div_const_b(uint8_t* input_a, uint8_t* input_b, uint8_t * output, const uint32_t length, const int p_bitcount, const int p_bitcount_const, const int p_bitcount_result) ;
            void big_com_and_sub(uint8_t* input_a, uint8_t* input_b, uint8_t* input_p, uint8_t* output, uint8_t* output_flag, const uint32_t length, const int p_bitcount, const int p_bitcount_const, const int p_bitcount_result);
            void mod_mul_const(uint8_t* input_a, uint8_t* input_b, uint8_t* input_p, uint8_t * output, const uint32_t length, const int p_bitcount);
            int dev_compiler(std::string operation_type,uint32_t str_len,uint32_t size,uint32_t p_bitcount,uint32_t e_bitcount,struct executor &executor_dat);
            void dev_gen_data(OPERATION_TYPE operation_type, uint8_t *a, uint8_t *b, uint8_t *n, uint32_t vec_size, std::vector<uint8_t> m_flg,uint32_t p_bitcount, uint32_t e_bitcount,uint8_t *output, bool split_flg,uint32_t a_len,uint32_t b_len,uint32_t n_len,uint32_t &offset);
            DEV_STATE dev_run(struct executor executor_dat,uint8_t *dat_in ,uint32_t dat_len,uint8_t *out);        
            DEV_STATE dev_alg_operation(std::string operation_name , uint8_t*a, uint32_t a_len,uint8_t *b,uint32_t b_len ,uint8_t *n,uint32_t n_len,uint32_t vec_size, uint32_t p_bitcount, uint32_t e_bitcount,uint8_t *output,uint32_t &output_len,std::vector<uint8_t> m_flg,bool split_flg=false);
            void paillier_decrypt_step2(struct _private_key private_key, uint32_t p_bitcount, uint32_t vec_size, uint8_t *plaintext_byte,uint32_t plaintext_byte_len,uint8_t *out,uint8_t *out_flg);
    };
}