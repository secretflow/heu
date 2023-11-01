// Copyright 2023 Polar Bear Tech (Xi 'an) Co., LTD.
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
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstdint>
#include <iostream>
#include <vector>
#include <cmath>
#include <stdio.h>
#include <unordered_map>
#include <sstream>
#include <map>
#include <iomanip>
#include <cstdint>
#include <bits/stdc++.h>

using int128_t = __int128_t;
using uint128_t = __uint128_t;

#define NUMBER_OF_CHIP    8
#define NUMBER_OF_PE      16
#define MAX_ON_CHIP_VECTOR 2048
#define GLOBAL_BUFFER_DEPTH 1024*1024*1024*2
#define LOCAL_INST_BUFFER_WIDTH 64
#define LOCAL_BUFFER_WIDTH 256
#define LOCAL_INST_BUFFER_DEPTH 16*1024
#define GLOBAL_BUFFER_WIDTH 8
#define GLOBAL_INST_BUFFER_DEPTH 4096

#define SOF                             0x00ffffff
#define ADDRESS_PIN_MUX                 0x00000068
#define ADDRESS_INST_FLAG               0x000000D0
#define DATA_PIN_MUX_PAD                0x00000000
#define DATA_OUT_TO_OUT_CTRL            0b111111111111111111

enum PE_STATE  {
    IDLE                                = 0b00000000,
    LOAD_PARA                           = 0b00000001,
    ELEMENT_RSQUARE                     = 0b00000010,
    ELE_MOD_MUL                         = 0b00000011,
    ELE_MOD_EXP                         = 0b00000100, 
    ELE_MOD_INV                         = 0b00000101,
    ELE_MOD_INV_P                       = 0b00000110,
    ELE_MOD_EXP_INV_EXP                 = 0b00110001,
    ELE_MOD_EXP_INV_MUL                 = 0b00110010,
    ELE_MOD_EXP_INV_COM                 = 0b00110011,
    ELE_MOD_EXP_EXP_EXP                 = 0b00110100,
    ELE_MOD_EXP_EXP_MUL                 = 0b00110101,
    ELE_MOD_EXP_EXP_COM                 = 0b00110110,
    VEC_OUTPUT_RESULTS                  = 0b00000111,
    SET_PSUM_CONV_ONLY                  = 0b00001000,
    CONV_ONLY                           = 0b00001001, 
    CONV_REDUCE_SINGLE_BIT              = 0b00001010,
    CONV_REDUCE_MULTI_PO_BIT            = 0b00001011, 
    CONV_REDUCE_MULTI_NA_BIT            = 0b00001100,
    CONV_REDUCE_MULTI_NA_1_BIT          = 0b00001101,
    SET_PSUM_INV_PLUS_CONV              = 0b00001110,
    MOD_INV_PLUS_CONV                   = 0b00001111,
    MOD_INV_CONV_REDUCE_SIGNLE_BIT      = 0b00010000,
    MOD_INV_CONV_REDUCE_MULTI_PO_BIT    = 0b00010001,
    MOD_INV_CONV_REDUCE_MULTI_NA_BIT    = 0b00010010,
    MOD_INV_CONV_REDUCE_MULTI_NA_1_BIT  = 0b00010011,
    CHECK_MOD_INV_FINISH                = 0b00010100,
    MOD_INV_REDUCE_PLUS_CONV            = 0b00010101,
    OUTPUT_RESULTS                      = 0b00010110,
    MOD_INV_ONLY                        = 0b00010111,
    MOD_INV_REDUCE_ONLY                 = 0b00011000,
    OUTPUT_RESULT                       = 0b00011001,
    COMPLETED                           = 0b11111111,
} ; 

enum DES_PE_TABLE {
    all                                = 0b101111,
    pe_group0                          = 0b100001, 
    pe_group1                          = 0b100010, 
    pe_group2                          = 0b100100, 
    pe_group3                          = 0b101000,
    pe_0                               = 0b000000, 
    pe_1                               = 0b000001, 
    pe_2                               = 0b000010, 
    pe_3                               = 0b000011,
    pe_4                               = 0b000100, 
    pe_5                               = 0b000101,
    pe_6                               = 0b000110,
    pe_7                               = 0b000111,
    pe_8                               = 0b001000, 
    pe_9                               = 0b001001,
    pe_10                              = 0b001010, 
    pe_11                              = 0b001011,
    pe_12                              = 0b001100, 
    pe_13                              = 0b001101,
    pe_14                              = 0b001110, 
    pe_15                              = 0b001111
};

enum  DES_REG_TABLE  {
    activation                         = 0b0000,
    a                                  = 0b0001,
    b                                  = 0b0010,
    weight                             = 0b0011,
    r_square                           = 0b0100,
    r_mont                             = 0b0101,
    n_prime                            = 0b0110,
    p                                  = 0b0111,
    param                              = 0b1000
};

enum DATA_TYPE {
    w_data                             = 0b000,
    w_inst                             = 0b001,
    w_inst_length                      = 0b010,
    inst_reset                         = 0b011,
    w_reg                              = 0b100,
    r_reg                              = 0b101
};

enum CAL_FLAG  {
    CAL                                 = 1,
    WAIT                                = 0,
};

enum  REPEAT_TABLE  {
    CHANGE                             =0b1, 
    NOCHANGE                           =0b0
};

struct DATA_IN{
    uint8_t p_bitcount;
    uint8_t e_bitcount;
};

struct MEM_CFG{
    uint8_t operation_type;
    uint8_t const_p_bitcount;
    uint8_t const_e_bitcount;
    uint8_t const_sram_data_width;
    uint8_t data_in_len;
    struct DATA_IN data_in[2];
};

struct INST_C_TABLE  {
    uint8_t operand; 
    PE_STATE pe_state;
    CAL_FLAG cal_flag;
    PE_STATE pe_n_state;
    uint32_t address;
    uint8_t pe_gate;
    uint32_t reserver;
};

struct Data_k_Info_t {
    std::string name;
    int const_p_bitcount;
    int const_e_bitcount;
    int const_sram_data_width;
    std::vector<std::map<std::string, float>> data_in;
};

uint64_t gen_inst_l(uint32_t address, uint32_t length, uint8_t des_pe, uint8_t des_reg, uint16_t times, bool change_flag, uint8_t pe_gate=0b1111);
uint64_t gen_inst_c(uint8_t pe_state, bool cal_flag, uint8_t pe_n_state, uint32_t address, uint8_t pe_gate=0b1111);
uint64_t gen_inst_i(uint64_t ddr_address,uint64_t ddr_length);
void check_inst_sram_depth(std::vector<uint64_t> _inst);
uint64_t gen_inst_none();
uint128_t gen_inst_r(uint16_t chip, uint8_t data_type, uint32_t data_address, uint32_t data);
uint128_t gen_inst_l1(uint16_t chip, uint32_t ddr_address, uint32_t ddr_length, uint8_t data_type, uint32_t data_address, bool bool_check=0);
uint128_t gen_inst_l2(uint16_t chip, uint16_t times);

struct out_ddr_detail_t{
    uint64_t out_ddr_addr;
    uint64_t out_ddr_length;
};

struct in_data_mem_alloc_t{
    uint64_t in_data_ddr_address_total;
    uint64_t in_data_ddr_length_total; 
    std::vector<std::vector<out_ddr_detail_t>> in_data_detail;
};

struct memory_allocation_t{
    uint64_t out_ddr_address_total;
    uint64_t out_ddr_length_total;
    std::vector<std::vector<std::vector<out_ddr_detail_t>>> out_detail;
    uint64_t inst_ddr_address_total;
    uint64_t inst_ddr_length_total;
    std::vector<std::vector<out_ddr_detail_t>> inst_detail;
    uint64_t in_para_ddr_address_total;
    uint64_t in_para_ddr_length_total;
    std::vector<in_data_mem_alloc_t> in_dat_ddr_mem_alloc;
    uint64_t last_ddr_address;
};

struct Program {
    std::string type;          
    std::string operation_type;     
    int vec_size;                
    int p_bitcount;             
    int e_bitcount;             
    int start_frequency;        
};

struct generator_inst_t{
    std::vector<uint64_t> inst;
    std::vector<uint32_t> inst_length;
};

struct _executor
{
    std::vector<uint8_t> inst;
    std::vector<uint8_t> inst_fpga;
    uint32_t in_para_address;
    uint32_t inst_address;
    uint32_t out_address;
    uint32_t out_length;
};

class generator_fpga
{
    public:
	    generator_fpga();
	    ~generator_fpga(){};
        void clear();
        void gen_inst(struct Program program,std::vector<std::vector<uint32_t>> task_split,struct memory_allocation_t memory_allocation,
        std::vector<std::vector<std::vector<uint64_t>>> inst,std::vector<std::vector<std::vector<uint32_t>>> inst_split);
        void _gen_inst_vector_(struct Program program,std::vector<std::vector<uint32_t>> task_split,struct memory_allocation_t memory_allocation,
        std::vector<std::vector<std::vector<uint64_t>>> inst,std::vector<std::vector<std::vector<uint32_t>>> inst_split);
        void __gen_inst_none__();
        void __gen_inst_pll_lock__();
        void __gen_inst_inst_reset__();
        void __gen_inst_inst_flag__(uint8_t chip_sel,uint32_t length);
        void __gen_inst_i__(){};
        void __gen_inst_w__(uint32_t address,uint32_t data);
        void __gen_inst_l1_wait__();
        void __gen_inst_vector_l1_data_para(struct memory_allocation_t __memory_allocation);
        void __gen_inst_vector_l1_data__(uint16_t chip,uint32_t task_split_first,struct memory_allocation_t __memory_allocation);
        void __gen_inst_vector_l1_inst__(uint16_t chip,uint32_t task_split_first,struct memory_allocation_t __memory_allocation);
        void __gen_inst_vector_r_inst_length_first__(uint16_t chip,uint32_t task_split_first,std::vector<std::vector<std::vector<uint32_t>>> __inst_split_asic);
        void __gen_inst_vector_r_inst_length_middle__(uint32_t task_split_first,std::vector<std::vector<std::vector<uint64_t>>> __inst_asic,std::vector<std::vector<std::vector<uint32_t>>> __inst_split_asic,std::vector<std::vector<uint32_t>> __task_split);
        void __gen_inst_vector_r_inst_length_last__(uint32_t task_split_first,std::vector<std::vector<std::vector<uint64_t>>> __inst_asic,std::vector<std::vector<std::vector<uint32_t>>> __inst_split_asic);
        void __gen_inst_vector_r_inst_length_add__(uint16_t chip_sel);
        void __gen_inst_c__(uint32_t chip_act_num,uint32_t pll_lock,uint32_t inst_flag);
    private:
        uint16_t chip_num;
        uint32_t ddr;
        uint32_t min_chip_true;
        uint32_t min_chip_false;
    public:
        std::vector<uint128_t> inst;
};

class generator_mont
{
    public:
        generator_mont();
        ~generator_mont(){}
        void Init(uint32_t& p_bitcount);
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
    public:
        Data_k_Info_t _k_dat;
};

class generator_mont_const
{
    public:
        generator_mont_const();
        ~generator_mont_const(){}
        void Init(uint32_t& p_bitcount);
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
    public:
        Data_k_Info_t _k_dat;
};

class generator_mod_mul
{
    public:
        generator_mod_mul();
        ~generator_mod_mul(){}
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
    public:
        Data_k_Info_t _k_dat;
};

class generator_mod_mul_const
{
    public:
        generator_mod_mul_const();
        ~generator_mod_mul_const(){}
        void Init(uint32_t& p_bitcount);
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
    public:
        Data_k_Info_t _k_dat;
};

class generator_mod_exp
{
    public:
        generator_mod_exp();
        ~generator_mod_exp(){}
        void Init(uint32_t& p_bitcount);
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
    public:
        Data_k_Info_t _k_dat;
};

class generator_mod_exp_const_e
{
    public:
        generator_mod_exp_const_e();
        ~generator_mod_exp_const_e(){}
        void Init(uint32_t& p_bitcount);
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
    public:
        Data_k_Info_t _k_dat;
};

class generator_mod_exp_const_a
{
    public:
        generator_mod_exp_const_a();
        ~generator_mod_exp_const_a(){}
        void Init(uint32_t& p_bitcount);
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
    public:
        Data_k_Info_t _k_dat;
};

class generator_mod_inv_const_p
{
    public:
        generator_mod_inv_const_p();
        ~generator_mod_inv_const_p(){}
        void Init(uint32_t& p_bitcount);
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
    public:
        Data_k_Info_t _k_dat;
};

class generator_paillier_encrypt
{
    public:
        generator_paillier_encrypt();
        ~generator_paillier_encrypt(){}
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
        uint32_t address_n;
        uint32_t address_g;
    public:
        Data_k_Info_t _k_dat;
};

class generator_mod_add
{
    public:
        generator_mod_add();
        ~generator_mod_add(){}
        void Init(uint32_t& p_bitcount);
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
    public:
        Data_k_Info_t _k_dat;
};

class generator_mod_add_const
{
    public:
        generator_mod_add_const();
        ~generator_mod_add_const(){}
        void Init(uint32_t& p_bitcount);
        void clear() ;
        struct generator_inst_t gen_inst(uint32_t p_bitcount,uint32_t e_bitcount,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc) ;
        void _inst_gen_start_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe) ;
        void _inst_gen_middle_(uint32_t p_bitcount,uint32_t e_bitcount,uint8_t actual_pe,uint32_t ddr_address,uint32_t ddr_length) ;
        void _inst_gen_end_(uint8_t actual_pe) ;
    private:
        std::vector<uint64_t> inst;
        std::vector<std::vector<uint32_t>> task_split;
        uint32_t inst_c_address;
        uint32_t inst_l_address;
        uint32_t task_split_n;
        uint32_t load_a_address;
        uint32_t load_b_address;
        std::vector<uint32_t> inst_length;
        uint32_t inst_length_last;
    public:
        Data_k_Info_t _k_dat;
};

class generator_asic 
{
    public:
        generator_asic() = default;
        struct generator_inst_t gen_inst(struct Program program,uint32_t task_split,std::vector<out_ddr_detail_t> mem_alloc);
        void gen_inst_para();
    private:
        std::vector<uint64_t> inst;
        std::vector<uint64_t> inst_split;
    public:
        std::string operation_type;
        auto _generator_sel_(std::string choice_generator_num);
};

class Compiler
{
    public:
        Compiler();
        ~Compiler(){    
            memory_allocation.last_ddr_address = 0;
            ddr_address = 0;
        }
        void clear();
        void get_k_dat(struct Program program);
        void set_device(uint8_t number_of_chip,uint8_t number_of_pe,uint64_t ddr);
        void compile();
        void _task_split_(struct Program program);
        void __task_split_vector__(struct Program program);
        void _memory_allocation_(struct Program program);
        void __memory_allocation_vector_out__(struct Program program);
        void __memory_allocation_vector_inst__(struct Program program);
        void __memory_allocation_vector_in_para__(struct Program program);
        bool __memory_allocation_vector_in_data_i__(struct Program program,uint32_t i_of_op);
        void __memory_allocation_vector_in_para___bak(MEM_CFG mem_cfg);
        void __gen_asic_inst__(struct Program program);
        void ___gen_asic_inst_vector___();
        void _gen_fpga_inst_(struct Program program);
        void check_mem(struct Program program);
        void _inst_reshape_(struct Program program);
        void get_executor();
        void data_inverse(uint8_t* data,uint32_t len);
        std::string to_string(uint128_t x);
    public:
        generator_asic _generator_asic;
        generator_fpga _generator_fpga;
    public:
        uint8_t num_of_chip;
        uint8_t num_of_pe;
        uint64_t ddr_size;
        uint64_t ddr_address;
        Data_k_Info_t _k_dat;
    public:
        struct Program _program;
        std::vector<std::vector<uint32_t>> task_split;
        std::vector<std::vector<std::vector<uint64_t>>> inst;
        std::vector<std::vector<std::vector<uint32_t>>> inst_split;
        struct memory_allocation_t memory_allocation;
        std::vector<uint8_t> inst_byte;
        struct _executor executor;
};
