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

#include "heu/library/algorithms/leichi_paillier/runtime.h"
#include <fstream>
namespace heu::lib::algorithms::leichi_paillier {
    bool Runtime::dev_connect()
    {
        if (pPcie.pcie_is_open())
            return true;
        return pPcie.open_device() > 0 ? true : false;
    }

    bool Runtime::dev_close()
    {
        pPcie.close_device();
        return OK;
    }

    size_t Runtime::dev_write_reg(size_t in_data, size_t addr)
    {
        return pPcie.write_reg(addr, in_data);
    }

    bool Runtime::dev_reset()
    {
        dev_write_reg(0,0x0010+0x24000);
        sleep(2); 
        dev_write_reg(1, 0x0010+0x24000);
        sleep(2); 
        return OK;
    }

    size_t Runtime::dev_read_reg(size_t *out_data, size_t addr)
    {
        return pPcie.read_reg(addr, (unsigned int *)out_data);
    }

    size_t Runtime::dev_write_ddr(uint8_t *in_data, size_t write_len, size_t addr)
    {
        if (pPcie.write_data(addr, in_data, write_len) < 1){
            return -1;
        }
        return write_len;
    }

    size_t Runtime::dev_read_ddr(uint8_t *out_data, size_t read_len, size_t addr)
    {
        if (pPcie.read_data(addr, out_data, read_len) < 1){
            return -1;
        }
        return read_len;
    }

    size_t Runtime::dev_write_init(uint8_t *in_data, size_t write_len, size_t addr)
    {
        if (pPcie.write_data_bypass(addr, in_data, write_len) < 1){
            return -1;
        }
        return write_len;
    }

    size_t Runtime::dev_read_init(uint8_t *out_data, size_t read_len, size_t addr)
    {
        return pPcie.read_data_bypass(addr, out_data, read_len);
    }

    size_t Runtime::dev_reset_device()
    {
        size_t ret1 = 0;
        size_t ret2 = 0;
        ret1 = dev_write_reg(0,0x0000+0x24000);
        usleep(1000);
        ret2 = dev_write_reg(1,0x0000+0x24000);
        usleep(1000);
        if(ret1 < 1 || ret1 > 100 ||  ret2 < 1 || ret2 > 100){
            return 0;
        }
        else{
            return 1;
        }
    }    

    size_t Runtime::api_write_inst(uint8_t *inst, size_t write_len,size_t addr)
    {
        return dev_write_init(inst, write_len,addr);
    }
        
    void Runtime::api_set_inst_length(size_t len)  
    {
        dev_write_reg(len, FPGA_SEND_BASE_ADDR+0x04);
        usleep(1000);
        dev_write_reg(1,FPGA_SEND_BASE_ADDR+0x08);
    }

    size_t Runtime::api_set_inst_length_clear()
    {
        size_t ret1 = 0;
        size_t ret2 = 0;
        ret1 = dev_write_reg(0, FPGA_SEND_BASE_ADDR+0x04);
        usleep(1000);
        ret2 = dev_write_reg(0,FPGA_SEND_BASE_ADDR+0x08);
        if(ret1 < 1 or ret1 > 100 or ret2 < 1 or ret2 > 100){
            return 1;
        }
        else{
            return 0;
        }
    }

    size_t Runtime::check_inst_pointer(size_t *out_data)
    {
        size_t addr = 0x0c+FPGA_SEND_BASE_ADDR;
        return dev_read_reg(out_data,addr);
    }

    void Runtime::vector_to_char_array(std::vector<uint8_t>& vec, unsigned char* &arr) 
    {
        arr = reinterpret_cast<unsigned char*>(vec.data());
    }

    void Runtime::char_array_to_vector(std::vector<uint8_t> &vec,unsigned char* buff,uint32_t buff_size)
    {
        for(uint32_t i=0;i<buff_size;i++){
            vec.push_back(buff[i]);
        }
    }

    OPERATION_TYPE Runtime::operation_trans(std::string operation)
    {
        OPERATION_TYPE operation_num=NONE;
        if("MONT" == operation)
            operation_num = MONT;
        else if("MONT_CONST" == operation)
            operation_num = MONT_CONST;
        else if("MOD_ADD" == operation)
            operation_num = MOD_ADD;
        else if(operation == "MOD_ADD_CONST")
            operation_num = MOD_ADD_CONST;
        else if(operation == "MOD_MUL_CONST")
            operation_num = MOD_MUL_CONST;
        else if(operation == "MOD_EXP")
            operation_num = MOD_EXP;
        else if(operation == "MOD_MUL")
            operation_num = MOD_MUL;
        else if(operation == "MOD_EXP_CONST_A")
            operation_num = MOD_EXP_CONST_A;
        else if(operation == "MOD_EXP_CONST_E")
            operation_num = MOD_EXP_CONST_E;
        else if(operation == "MOD_EXP_CONST_A")
            operation_num = MOD_EXP_CONST_A;
        else if(operation == "PAILLIER_ENC")
            operation_num = PAILLIER_ENC;
        else if(operation == "MOD_INV_CONST_P")
            operation_num = MOD_INV_CONST_P;
        else if(operation == "MOD_INV")
            operation_num = MOD_INV;
        return operation_num;
    }

    int Runtime::get_p_bitcount_chip(uint32_t p_bitcount)
    {
        uint32_t count = 0;
        switch(p_bitcount){
            case 4096:
                count = 5;
                break;
            case 3072:
                count = 4;
                break;
            case 2048:
                count = 3;
                break;
            case 1024:
                count = 2;
                break;
            case 512:
                count = 1;
                break;
        }   
        return count;
    }

    void Runtime::data_inverse(uint8_t* data,uint32_t len)
    {
        uint32_t i = 0;
        uint8_t tmp;
        for(i=0;i<len/2;i++)
        {
            tmp = data[len-1-i];
            data[len-1-i] = data[i];
            data[i] = tmp;
        }
    }

    int Runtime::gen_param(uint32_t kernels, uint32_t p_bitcount, uint32_t case_v, uint32_t e_bitcount, uint32_t bool_ele_r_square, uint32_t bits)
    {
        int  para = 0;
        para += ((kernels % (int)(pow(2, 39))) << 25);
        para += ((p_bitcount % (int)(pow(2, 3))) << 22);
        para += ((case_v % (int)(pow(2, 3))) << 19);
        para += ((e_bitcount % (int)(pow(2, 13))) << 6);
        para += ((bool_ele_r_square % (int)(pow(2, 1))) << 5);
        para += ((bits % (int)(pow(2, 5))) << 0);
        return para;
    }

    void Runtime::gen_mont_para(BIGNUM *p, uint32_t p_bitcount,uint8_t*output,uint32_t &len)
    {
        int block_len       = 256;
        BIGNUM *temp        = BN_new();
        BIGNUM *bn_n_prime  = BN_new();
        BIGNUM *bn_r_square = BN_new();
        BN_CTX *bn_ctx      = BN_CTX_new();
        len                 = 0;

        BN_lshift(bn_r_square, BN_value_one(), block_len);
        BN_mod_inverse(bn_n_prime, p, bn_r_square, bn_ctx);
        BN_zero(temp);
        BN_sub(bn_n_prime, temp, bn_n_prime);
        BN_nnmod(bn_n_prime, bn_n_prime, bn_r_square, bn_ctx);
        BN_lshift(bn_r_square, BN_value_one(), 2 * (p_bitcount));
        BN_mod(bn_r_square, bn_r_square, p, bn_ctx);

        BN_bn2binpad(bn_n_prime,output+len,BYTECOUNT(block_len));
        data_inverse(output+len,BYTECOUNT(block_len));

        len += BYTECOUNT(block_len);
        BN_bn2binpad(bn_r_square,output+len,BYTECOUNT(p_bitcount));
        data_inverse(output+len,BYTECOUNT(p_bitcount));
        len += BYTECOUNT(p_bitcount);

        BN_free(temp);
        BN_free(bn_n_prime);
        BN_free(bn_r_square);
        BN_CTX_free(bn_ctx);
    }

    void Runtime::gen_p_mont_para(BIGNUM *p, uint32_t p_bitcount,uint8_t*output,uint32_t &len,uint8_t flg)
    {
        uint32_t block_len       = 256;
        BIGNUM *temp        = BN_new();
        BIGNUM *temp1        = BN_new();
        BIGNUM *temp2        = BN_new();
        BIGNUM *bn_n_prime  = BN_new();
        BIGNUM *bn_r_square = BN_new();
        BN_CTX *bn_ctx      = BN_CTX_new();
        BIGNUM *bn_r = BN_new();
        BIGNUM *bn_s = BN_new();
        BIGNUM *bn_x = BN_new();
        BIGNUM *bn_y = BN_new();
        BIGNUM *bn_p = BN_new();
        BIGNUM *bn_s_0 = BN_new();
        BIGNUM *bn_x_0 = BN_new();
        BIGNUM *bn_y_i = BN_new();
        BIGNUM *bn_q = BN_new();
        len                 = 0;

        BN_lshift(bn_r_square, BN_value_one(), block_len);
        BN_mod_inverse(bn_n_prime, p, bn_r_square, bn_ctx);
        BN_zero(temp);
        BN_sub(bn_n_prime, temp, bn_n_prime);
        BN_nnmod(bn_n_prime, bn_n_prime, bn_r_square, bn_ctx);

        BN_lshift(bn_r_square, BN_value_one(), 2 * (p_bitcount));
        BN_mod(bn_r_square, bn_r_square, p, bn_ctx);
        BN_lshift(bn_r, BN_value_one(), block_len);
        BN_one(bn_x);
        BN_set_word(bn_s, 0);
        BN_set_word(bn_x_0,0);
        BN_set_word(bn_s_0,0);
        BN_set_word(bn_y_i,0);
        BN_set_word(bn_q,0);
        BN_zero(temp1);
        BN_zero(temp2);
        uint32_t len_tmp = 0;
        for (uint32_t i = 0; i < p_bitcount/block_len; i++) {
            BN_mod(bn_s_0, bn_s, bn_r, bn_ctx);
            BN_mod(bn_x_0, bn_x, bn_r, bn_ctx);
            len_tmp = block_len*i;
            BN_rshift(bn_y_i, bn_r_square, len_tmp);
            BN_mod(bn_y_i, bn_y_i, bn_r, bn_ctx);
            BN_mul(bn_q, bn_x_0, bn_y_i, bn_ctx);
            BN_add(bn_q, bn_q, bn_s_0);
            BN_mul(bn_q, bn_q, bn_n_prime, bn_ctx);
            BN_mod(bn_q, bn_q, bn_r, bn_ctx);
            BN_mul(temp1, bn_x, bn_y_i, bn_ctx);
            BN_mul(temp2, bn_q, p, bn_ctx);
            BN_add(bn_s, temp1, bn_s);
            BN_add(bn_s, bn_s, temp2);
            BN_rshift(bn_s, bn_s, block_len);
        }    
        BN_bn2binpad(bn_n_prime,output+len,BYTECOUNT(block_len));
        data_inverse(output+len,BYTECOUNT(block_len));
        len += BYTECOUNT(block_len);

        if(flg==1){
            BN_bn2binpad(bn_r_square,output+len,BYTECOUNT(p_bitcount));
            data_inverse(output+len,BYTECOUNT(p_bitcount));
            len += BYTECOUNT(p_bitcount);
        }
        else if(flg==2){
            BN_bn2binpad(bn_r_square,output+len,BYTECOUNT(p_bitcount));
            data_inverse(output+len,BYTECOUNT(p_bitcount));
            len += BYTECOUNT(p_bitcount);

            BN_bn2binpad(bn_s,output+len,BYTECOUNT(p_bitcount));
            data_inverse(output+len,BYTECOUNT(p_bitcount));
            len += BYTECOUNT(p_bitcount);
        }
        else if(flg == 3){;}

        BN_free(bn_r);
        BN_free(bn_s);
        BN_free(bn_x);
        BN_free(bn_y);
        BN_free(bn_p);
        BN_free(bn_n_prime);
        BN_free(bn_s_0);
        BN_free(bn_x_0);
        BN_free(bn_y_i);
        BN_free(bn_q);
        BN_free(temp);
        BN_free(temp1);
        BN_free(temp2);
        BN_free(bn_r_square);
        BN_CTX_free(bn_ctx);
    }

    int Runtime::dev_compiler(std::string operation_type,uint32_t str_len,uint32_t size,uint32_t p_bitcount,uint32_t e_bitcount,struct executor &executor_dat)
    {
        compiler._program.type = "vector";
        compiler._program.operation_type = operation_type;
        compiler._program.p_bitcount = p_bitcount;
        compiler._program.e_bitcount = e_bitcount;
        compiler._program.vec_size = size;
        compiler.compile();
        executor_dat.inst = compiler.executor.inst;
        executor_dat.inst_fpga = compiler.executor.inst_fpga;
        executor_dat.in_para_address = compiler.executor.in_para_address;
        executor_dat.inst_address = compiler.executor.inst_address;
        executor_dat.out_address = compiler.executor.out_address;
        executor_dat.out_length = compiler.executor.out_length;
        return 0;
    }

    void Runtime::dev_gen_data(OPERATION_TYPE operation_type, uint8_t *a, uint8_t *b, uint8_t *n, uint32_t vec_size, std::vector<uint8_t> m_flg,uint32_t p_bitcount, uint32_t e_bitcount,uint8_t *output, bool split_flg,uint32_t a_len,uint32_t b_len,uint32_t n_len,uint32_t &offset)
    {
        offset = 0;
        uint32_t mont_len = 0;
        int kernels = 0;
        int case_v = 0b000;
        int bool_ele_r_square = 0;
        int bits = 0;
        int para = 0;
        
        BIGNUM *_n = BN_new();
        int para_p_bitcount = get_p_bitcount_chip(p_bitcount);
        if(operation_type == MOD_ADD || operation_type == MOD_ADD_CONST ) {case_v = 0b001;}
        uint8_t para_bytes[32];
        memset(para_bytes,0,32);
        if(operation_type == PAILLIER_ENC){
            para = gen_param(kernels, para_p_bitcount, case_v, p_bitcount, bool_ele_r_square, bits);
            memcpy((uint8_t *)(output+offset),(uint8_t *)&para,sizeof(para));
            
            offset += 32;
            BN_bin2bn(n, BYTECOUNT(p_bitcount/2), _n);
        }
        else if(operation_type == MOD_INV_CONST_P){
            para = gen_param(kernels, para_p_bitcount, case_v, e_bitcount, bool_ele_r_square, bits);
            memcpy((uint8_t *)(output+offset),(uint8_t *)&para,sizeof(para));
            memcpy((uint8_t *)para_bytes,(uint8_t *)&para,sizeof(para));
            offset += 32;
            BN_bin2bn(n, BYTECOUNT(p_bitcount/2), _n);
        }
        else{
            para = gen_param(kernels, para_p_bitcount, case_v, e_bitcount, bool_ele_r_square, bits);
            memcpy((uint8_t *)(output+offset),(uint8_t *)&para,sizeof(para));
            offset += 32;
            if(split_flg){
                BN_bin2bn(n, BYTECOUNT(p_bitcount/2), _n);
            }
            else{
                BN_bin2bn(n, BYTECOUNT(p_bitcount), _n);
            }  
        }

        BIGNUM *pubkey_nsquare = BN_new();
        BIGNUM *pubkey_g = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *temp = BN_new();
        BIGNUM *temp1 = BN_new();
        BN_CTX *bn_ctx      = BN_CTX_new();

        if(operation_type == PAILLIER_ENC){
            BN_mul(pubkey_nsquare,_n,_n,bn_ctx);
            BN_bn2binpad(pubkey_nsquare,output+offset,BYTECOUNT(p_bitcount));
            data_inverse(output+offset,BYTECOUNT(p_bitcount));
            offset += BYTECOUNT(p_bitcount);
        }
        else if(operation_type == MOD_INV_CONST_P){;}
        else{
            if(split_flg){
                BN_mul(pubkey_nsquare,_n,_n,bn_ctx);
                BN_bn2binpad(pubkey_nsquare,output+offset,BYTECOUNT(p_bitcount));
            }
            else{
                BN_bn2binpad(_n,output+offset,BYTECOUNT(p_bitcount));
            }
            
            data_inverse(output+offset,BYTECOUNT(p_bitcount));
            offset += BYTECOUNT(p_bitcount);
        }

        if(operation_type == PAILLIER_ENC){
            gen_p_mont_para(pubkey_nsquare,p_bitcount, (uint8_t *)(output+offset),mont_len,2);
            offset += mont_len;

            BN_lshift(temp1, _n, 1);
            BN_bn2binpad(temp1,output+offset,BYTECOUNT(p_bitcount));
            data_inverse(output+offset,BYTECOUNT(p_bitcount));
            offset += BYTECOUNT(p_bitcount);

            BN_add(pubkey_g,_n,BN_value_one());
            BN_bn2binpad(pubkey_g,output+offset,BYTECOUNT(p_bitcount));
            data_inverse(output+offset,BYTECOUNT(p_bitcount));
            offset += BYTECOUNT(p_bitcount);
        }
        else if(operation_type == MOD_INV_CONST_P){;}
        else{
            if(operation_type == MONT || operation_type==MONT_CONST){
                gen_p_mont_para(pubkey_nsquare,p_bitcount, (uint8_t *)(output+offset),mont_len,0);
                offset += mont_len;
            }
            else if(operation_type == MOD_ADD || operation_type==MOD_ADD_CONST){;}
            else{
                if(split_flg){
                    BN_mul(pubkey_nsquare,_n,_n,bn_ctx);
                    gen_mont_para(pubkey_nsquare,p_bitcount, (uint8_t *)(output+offset),mont_len);
                    offset += mont_len;
                }
                else{
                    gen_mont_para(_n,p_bitcount, (uint8_t *)(output+offset),mont_len);
                    offset += mont_len;
                }
            }
        }

        uint32_t a_offset=0 ;
        uint32_t b_offset=0 ;
        uint32_t number_of_outs = std::ceil((float)vec_size/16.0);
        uint32_t last_number = 0;
        uint32_t numbers = 0;
        uint8_t x= 0;
        std::vector<uint8_t> xx;
        switch(operation_type){
            case MOD_INV:
                break;
            case MONT:
                for(uint32_t i=0;i<vec_size;i++){
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),BYTECOUNT(p_bitcount));
                    data_inverse(output+offset,BYTECOUNT(p_bitcount));
                    offset += BYTECOUNT(p_bitcount);
                    a_offset += BYTECOUNT(p_bitcount);
                }
                for(uint32_t i=0;i<vec_size;i++){
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),BYTECOUNT(p_bitcount));
                    data_inverse(output+offset,BYTECOUNT(p_bitcount));
                    offset += BYTECOUNT(p_bitcount);
                    b_offset += BYTECOUNT(p_bitcount);
                }
                break;
            case MONT_CONST:
                memcpy((uint8_t *)(output+offset),(uint8_t *)(b),BYTECOUNT(p_bitcount));
                data_inverse(output+offset,BYTECOUNT(p_bitcount));
                offset += BYTECOUNT(p_bitcount);
                for(uint32_t i=0;i<vec_size;i++){                    
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),BYTECOUNT(p_bitcount));
                    data_inverse(output+offset,BYTECOUNT(p_bitcount));
                    offset += BYTECOUNT(p_bitcount);
                    a_offset += BYTECOUNT(p_bitcount);
                }
                break;
            case MOD_MUL:
                if(split_flg){
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),a_len);
                    offset += a_len;
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),b_len);
                    offset += b_len;
                }
                else{
                    for(uint32_t i=0;i<vec_size;i++){
                        memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),BYTECOUNT(p_bitcount));
                        data_inverse(output+offset,BYTECOUNT(p_bitcount));
                        offset += BYTECOUNT(p_bitcount);
                        a_offset += BYTECOUNT(p_bitcount);
                    }
                    for(uint32_t i=0;i<vec_size;i++){
                        memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),BYTECOUNT(p_bitcount));
                        data_inverse(output+offset,BYTECOUNT(p_bitcount));
                        offset += BYTECOUNT(p_bitcount);
                        b_offset += BYTECOUNT(p_bitcount);
                    }
                }  
                break;
            case MOD_MUL_CONST:
                memcpy((uint8_t *)(output+offset),(uint8_t *)(b),BYTECOUNT(p_bitcount));
                data_inverse(output+offset,BYTECOUNT(p_bitcount));
                offset += BYTECOUNT(p_bitcount);
                for(uint32_t i=0;i<vec_size;i++){                    
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),BYTECOUNT(p_bitcount));
                    data_inverse(output+offset,BYTECOUNT(p_bitcount));
                    offset += BYTECOUNT(p_bitcount);
                    a_offset += BYTECOUNT(p_bitcount);
                }
                break;
            case MOD_EXP:
                if(split_flg){
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),a_len);
                    offset += a_len;
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),b_len);   
                    offset += b_len;
                }
                else{
                    for(uint32_t i=0;i<vec_size;i++){
                        memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),BYTECOUNT(p_bitcount));
                        data_inverse(output+offset,BYTECOUNT(p_bitcount));
                        offset += BYTECOUNT(p_bitcount);
                        a_offset += BYTECOUNT(p_bitcount);
                    }
                    for(uint32_t i=0;i<vec_size;i++){
                        memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),BYTECOUNT(e_bitcount));
                        data_inverse(output+offset,BYTECOUNT(e_bitcount));
                        offset += BYTECOUNT(e_bitcount);
                        b_offset += BYTECOUNT(e_bitcount);
                    }
                }
                break;
            case MOD_EXP_CONST_A:
                memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),BYTECOUNT(p_bitcount));
                data_inverse(output+offset,BYTECOUNT(p_bitcount));
                offset += BYTECOUNT(p_bitcount);

                for(uint32_t i=0;i<vec_size;i++){                    
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),BYTECOUNT(e_bitcount));
                    data_inverse(output+offset,BYTECOUNT(e_bitcount));
                    offset += BYTECOUNT(e_bitcount);
                    b_offset += BYTECOUNT(e_bitcount);
                }
                break;
            case MOD_EXP_CONST_E:
                if(split_flg){
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),b_len);
                    data_inverse(output+offset,b_len);
                    offset += b_len;
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),a_len);
                    offset += a_len;
                }
                else{
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),BYTECOUNT(e_bitcount));
                    data_inverse(output+offset,BYTECOUNT(e_bitcount));
                    offset += BYTECOUNT(e_bitcount);
                    for(uint32_t i=0;i<vec_size;i++){                    
                        memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),BYTECOUNT(p_bitcount));
                        data_inverse(output+offset,BYTECOUNT(p_bitcount));
                        offset += BYTECOUNT(p_bitcount);
                        a_offset += BYTECOUNT(p_bitcount);
                    }
                }
                break;
            case MOD_INV_CONST_P:
                if(split_flg){
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),BYTECOUNT(p_bitcount));
                    data_inverse(output+offset,BYTECOUNT(p_bitcount));
                    offset += BYTECOUNT(p_bitcount);
                    for(uint32_t i=0;i<number_of_outs;i++){
                        last_number = ((vec_size%16)==0)?16:(vec_size%16);
                        numbers = (i == (number_of_outs-1))? last_number:16;
                        for(uint32_t j = 0; j<numbers;j++)
                            for(uint32_t k = 0;k<(p_bitcount/8);k++)
                            {
                                x = a[(i*16+j)*(p_bitcount/8)+k];
                                xx.push_back(x);
                            }
                    }
                    memcpy((uint8_t *)(output+offset),xx.data(),xx.size());                   
                    offset += xx.size();
                }
                break;
            case MOD_ADD:
                for(uint32_t i=0;i<vec_size;i++){
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),BYTECOUNT(p_bitcount));
                    data_inverse(output+offset,BYTECOUNT(p_bitcount));
                    offset += BYTECOUNT(p_bitcount);
                    a_offset += BYTECOUNT(p_bitcount);
                }
                for(uint32_t i=0;i<vec_size;i++){
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),BYTECOUNT(p_bitcount));
                    data_inverse(output+offset,BYTECOUNT(p_bitcount));
                    offset += BYTECOUNT(p_bitcount);
                    b_offset += BYTECOUNT(p_bitcount);
                }
                break;
            case MOD_ADD_CONST:
                memcpy((uint8_t *)(output+offset),(uint8_t *)(b+b_offset),BYTECOUNT(p_bitcount));
                data_inverse(output+offset,BYTECOUNT(p_bitcount));
                offset += BYTECOUNT(p_bitcount);

                for(uint32_t i=0;i<vec_size;i++){                    
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),BYTECOUNT(p_bitcount));
                    data_inverse(output+offset,BYTECOUNT(p_bitcount));
                    offset += BYTECOUNT(p_bitcount);
                    a_offset += BYTECOUNT(p_bitcount);
                }
                break;
            case PAILLIER_ENC:
                for(uint32_t i=0;i<vec_size;i++){                    
                    BN_bin2bn(b+b_offset, BYTECOUNT(p_bitcount/2), m);
                    BN_lshift(temp, m, 1);
                    if(m_flg[i] ==1){
                        BN_add_word(temp,1);
                    }    
                    
                    BN_bn2binpad(temp,output+offset,BYTECOUNT(p_bitcount/2));
                    uint8_t tmp_before[2048];
                    memset(tmp_before,0,2048);
                    memcpy(tmp_before,output+offset,BYTECOUNT(p_bitcount/2));
                    data_inverse(output+offset,BYTECOUNT(p_bitcount/2));
                    uint8_t tmp[2048];
                    memset(tmp,0,2048);
                    memcpy(tmp,output+offset,BYTECOUNT(p_bitcount/2));
                    offset += BYTECOUNT(p_bitcount)/2;
                    b_offset += BYTECOUNT(p_bitcount/2);
                }
                for(uint32_t i=0;i<vec_size;i++){
                    memcpy((uint8_t *)(output+offset),(uint8_t *)(a+a_offset),BYTECOUNT(p_bitcount/2));
                    data_inverse(output+offset,BYTECOUNT(p_bitcount/2));
                    offset += BYTECOUNT(p_bitcount/2);
                    a_offset += BYTECOUNT(p_bitcount/2);
                }
                break;
            default:
                break;
        }
        BN_free(_n);
        BN_free(pubkey_nsquare);
        BN_free(pubkey_g);
        BN_free(m);
        BN_free(temp);
        BN_CTX_free(bn_ctx);
    }

    void writeBin(char *path, uint8_t *buf, uint32_t size)
    {
        FILE *outfile;

        if ((outfile = fopen(path, "wb")) == NULL)
        {
            printf("\nCan not open the path: %s \n", path);
            exit(-1);
        }
        fwrite(buf, sizeof(uint8_t), size, outfile);
        fclose(outfile);
    }

    DEV_STATE Runtime::dev_run(struct executor executor_dat,uint8_t *dat_in ,uint32_t dat_len,uint8_t *out)
    {
        DEV_STATE  status = OK;
        size_t cur_val = 0;
        uint32_t time_cnt = 0;
        if(!dev_reset_device()){return Failed;}

        if (!dev_write_ddr(dat_in, dat_len, executor_dat.in_para_address)){
            status = Write_Faild;
            return status;
        }

        if (!dev_write_ddr(executor_dat.inst.data(), executor_dat.inst.size(),executor_dat.inst_address)){
            std::cout << "dev_write_ddr inst wrong! \n" <<std::endl;
            status = Write_Faild;
            return status;
        } 

        if (!api_write_inst(executor_dat.inst_fpga.data(), executor_dat.inst_fpga.size(),0)){
            status = Write_Faild;
            return status;
        }
   
        uint32_t inst_fpga_len = executor_dat.inst_fpga.size()/16-1;
        api_set_inst_length(inst_fpga_len);

        while (1){
            check_inst_pointer(&cur_val);
            if((time_cnt %100) == 0){}
            if (cur_val >= 1){
                status = OK;
                break;
            } 
            if(time_cnt>100000){
                status = Time_out;
                break;
            }
            usleep(1000);
            time_cnt ++;
        }
        api_set_inst_length_clear();
        dev_read_ddr(out, executor_dat.out_length, executor_dat.out_address);
        dev_reset_device();
        return status; 
    }

    DEV_STATE Runtime::dev_alg_operation(std::string operation_name , uint8_t*a, uint32_t a_len,uint8_t *b,uint32_t b_len ,uint8_t *n,uint32_t n_len,uint32_t vec_size, uint32_t p_bitcount, uint32_t e_bitcount,uint8_t *output,uint32_t &output_len,std::vector<uint8_t> m_flg,bool split_flg)
    {
        uint32_t input_len=0;
        DEV_STATE  status = OK;
        OPERATION_TYPE operation_type;
        struct executor executor_dat;
        output_len = 0;
        uint32_t input_size = 0;
        input_size = BYTECOUNT(p_bitcount)*vec_size+5*BYTECOUNT(p_bitcount)+2*BYTECOUNT(256)+BYTECOUNT(p_bitcount)*vec_size;
        uint8_t *input = new uint8_t[input_size];
        memset(input,0x00,input_size);
        operation_type = operation_trans(operation_name);
        dev_gen_data(operation_type, a, b, n, vec_size, m_flg,p_bitcount, e_bitcount,input, split_flg,a_len,b_len,n_len,input_len);
        dev_compiler(operation_name.c_str(),operation_name.length(),vec_size,p_bitcount,e_bitcount,executor_dat);
        dev_run(executor_dat,input,input_len,output);
        output_len = executor_dat.out_length;
        delete [] input;
        return status;
    }

    void Runtime::big_sub_const_b(uint8_t* input_a, uint8_t* input_b, uint8_t * output, const uint32_t length, const int p_bitcount, const int p_bitcount_const) 
    {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();

        BN_bin2bn((unsigned char*)input_b, BYTECOUNT(p_bitcount_const), b);
        uint32_t offset = 0;
        for (uint32_t i = 0; i < length; i++) {
            BN_bin2bn((unsigned char*)(input_a + offset), BYTECOUNT(p_bitcount), a);
            BN_sub(result, a, b);
            BN_bn2binpad(result, (unsigned char*)(output + offset), BYTECOUNT(p_bitcount));
            offset += BYTECOUNT(p_bitcount);
        }
        
        BN_free(a);
        BN_free(b);
        BN_free(result);
    }

    void Runtime::big_div_const_b(uint8_t* input_a, uint8_t* input_b, uint8_t * output, const uint32_t length, const int p_bitcount, const int p_bitcount_const, const int p_bitcount_result) 
    {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();
        BIGNUM *rem = BN_new();
        BN_CTX *bn_ctx = BN_CTX_new();

        BN_bin2bn((unsigned char*)input_b, BYTECOUNT(p_bitcount_const), b);
        uint32_t offset = 0;
        uint32_t offset_result = 0;
        for (uint32_t i = 0; i < length; i++) {
            BN_bin2bn((unsigned char*)(input_a + offset), BYTECOUNT(p_bitcount), a);
            BN_div(result, rem, a, b, bn_ctx);
            BN_bn2binpad(result, (unsigned char*)(output + offset_result), BYTECOUNT(p_bitcount_result));
            offset += BYTECOUNT(p_bitcount);
            offset_result += BYTECOUNT(p_bitcount_result);
        }
        
        BN_free(a);
        BN_free(b);
        BN_free(result);
        BN_free(rem);
        BN_CTX_free(bn_ctx);
    }

    void Runtime::big_com_and_sub(uint8_t* input_a, uint8_t* input_b, uint8_t* input_p, uint8_t* output, uint8_t* output_flag, const uint32_t length, const int p_bitcount, const int p_bitcount_const, const int p_bitcount_result) 
    {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *p = BN_new();
        BIGNUM *result = BN_new();
        BN_CTX *bn_ctx = BN_CTX_new();

        BN_bin2bn((unsigned char*)input_b, BYTECOUNT(p_bitcount_const), b);
        BN_bin2bn((unsigned char*)input_p, BYTECOUNT(p_bitcount_const), p);
        uint32_t offset = 0;
        uint32_t offset_result = 0;
        int32_t com_bool = 0;
        for (uint32_t i = 0; i < length; i++) {
            BN_bin2bn((unsigned char*)(input_a + offset), BYTECOUNT(p_bitcount), a);
            com_bool = BN_cmp(a, b);
            if(com_bool>=0) {
                output_flag[i] = 1;
                BN_sub(result, p, a);
                BN_bn2binpad(result, (unsigned char*)(output + offset_result), BYTECOUNT(p_bitcount_result));
            }
            else{
                output_flag[i] = 0;
                BN_bn2binpad(a, (unsigned char*)(output + offset_result), BYTECOUNT(p_bitcount_result));
            }
            
            offset += BYTECOUNT(p_bitcount);
            offset_result += BYTECOUNT(p_bitcount_result);
        }   
        BN_free(a);
        BN_free(b);
        BN_free(p);
        BN_free(result);
        BN_CTX_free(bn_ctx);
    }

    void Runtime::mod_mul_const(uint8_t* input_a, uint8_t* input_b, uint8_t* input_p, uint8_t * output, const uint32_t length, const int p_bitcount) {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *p = BN_new();
        BIGNUM *result = BN_new();
        BN_CTX *bn_ctx = BN_CTX_new();

        BN_bin2bn((unsigned char*)input_p, BYTECOUNT(p_bitcount), p);
        BN_bin2bn((unsigned char*)input_b, BYTECOUNT(p_bitcount), b);
        uint32_t offset = 0;
        for (uint32_t i = 0; i < length; i++) {
            BN_bin2bn((unsigned char*)(input_a + offset), BYTECOUNT(p_bitcount), a);
            BN_mod_mul(result, a, b, p, bn_ctx);
            BN_bn2binpad(result, (unsigned char*)(output + offset), BYTECOUNT(p_bitcount));
            offset += BYTECOUNT(p_bitcount);
        }   
        BN_free(a);
        BN_free(b);
        BN_free(p);
        BN_free(result);
        BN_CTX_free(bn_ctx);
    }

    void Runtime::paillier_decrypt_step2(struct _private_key private_key, uint32_t p_bitcount, uint32_t vec_size, uint8_t *plaintext_byte,uint32_t plaintext_byte_len,uint8_t *out,uint8_t *out_flg){
        uint32_t p_bitcount_const = 8;
        uint32_t p_bitcount_result = 0;
        BIGNUM *p = BN_new();
        BIGNUM *q = BN_new();
        BIGNUM *n = BN_new();
        BIGNUM *g = BN_new();
        BIGNUM *mu = BN_new();
        BIGNUM *n_square = BN_new();
        BIGNUM *lamda = BN_new();
        BIGNUM *rem = BN_new();
        BIGNUM *temp = BN_new();
        BIGNUM *temp_1 = BN_new();
        BN_CTX *bn_ctx  = BN_CTX_new();
        BN_CTX *bn_n_ctx  = BN_CTX_new();

        uint8_t * p_buff;
        uint8_t * q_buff;
        vector_to_char_array(private_key.p,p_buff);
        BN_bin2bn(p_buff, private_key.p.size(), p);

        vector_to_char_array(private_key.q,q_buff);
        BN_bin2bn(q_buff, private_key.q.size(), q);

        BN_mul(n,p,q,bn_n_ctx);
        BN_sub(p, p,BN_value_one());
        BN_sub(q, q,BN_value_one());
        BN_mul(lamda,p,q,bn_ctx);
        BN_mul(n_square,n,n,bn_ctx);
        BN_add(g,n,BN_value_one());

        BN_mod_mul(mu, g, lamda, n_square, bn_ctx);
        BN_sub(mu,mu,BN_value_one());
        BN_div(mu,rem,mu,n,bn_ctx);
        BN_mod_inverse(mu,mu,n,bn_ctx);

        uint8_t *result = new uint8_t[vec_size*BYTECOUNT(p_bitcount)];
        memset(result,0,vec_size*BYTECOUNT(p_bitcount));
        uint8_t b_bytes[1]={1};
        data_inverse(plaintext_byte,plaintext_byte_len);
        big_sub_const_b(plaintext_byte, b_bytes, result, vec_size, p_bitcount, p_bitcount_const);

        p_bitcount_const = p_bitcount/2;
        p_bitcount_result = p_bitcount/2;
        uint8_t n_bytes[BYTECOUNT(p_bitcount/2)];
        memset(n_bytes,0,BYTECOUNT(p_bitcount/2));
        BN_bn2binpad(n, (unsigned char*)(n_bytes), BYTECOUNT(p_bitcount/2));

        uint8_t *div_result = new uint8_t[vec_size*BYTECOUNT(p_bitcount)];
        memset(div_result,0,vec_size*BYTECOUNT(p_bitcount));

        big_div_const_b(result, n_bytes, div_result, vec_size, p_bitcount, p_bitcount_const, p_bitcount_result);

        uint8_t mu_bytes[BYTECOUNT(p_bitcount/2)];
        memset(mu_bytes,0,BYTECOUNT(p_bitcount/2));

        BN_bn2binpad(mu, (unsigned char*)(mu_bytes), BYTECOUNT(p_bitcount/2));

        uint8_t *mul_result = new uint8_t[vec_size*BYTECOUNT(p_bitcount)];
        memset(mul_result,0,vec_size*BYTECOUNT(p_bitcount));
        uint32_t p_bitcount_c = p_bitcount/2;

        mod_mul_const(div_result, mu_bytes, n_bytes, mul_result, vec_size, p_bitcount_c);
        BN_set_word(temp,2);
        BN_mul(temp,temp,n,bn_ctx);
        BN_set_word(temp_1,3);
        BN_div(temp,rem,temp,temp_1,bn_ctx);
        uint8_t temp_bytes[BYTECOUNT(p_bitcount/2)];
        memset(temp_bytes,0,BYTECOUNT(p_bitcount/2));
        BN_bn2binpad(temp, (unsigned char*)(temp_bytes), BYTECOUNT(p_bitcount/2));
        big_com_and_sub(mul_result, temp_bytes, n_bytes, out, out_flg, vec_size, p_bitcount_c, p_bitcount_const, p_bitcount_result);
        BN_free(p);
        BN_free(q);
        BN_free(n);
        BN_free(g);
        BN_free(n_square);
        BN_free(lamda);
        BN_free(rem);
        BN_free(temp);
        BN_free(temp_1);
        BN_free(mu);
        BN_CTX_free(bn_ctx);
        BN_CTX_free(bn_n_ctx);

        delete [] div_result;
        delete [] mul_result;
        delete [] result;
    }
// }

DEV_STATE Runtime::paillier_encrypt(uint8_t *m,uint8_t *r,std::vector<uint8_t> m_flg,uint32_t vec_size,struct _public_key public_key,uint8_t *output,uint32_t &output_len)
{
    bool split_flg = true;
    DEV_STATE  status = OK;
    std::string operation_name = "PAILLIER_ENC";
    BIGNUM *n = BN_new();
    uint32_t p_bitcount = 2*public_key.n_bitcount;
    uint32_t e_bitcount = p_bitcount/2;
    uint8_t * n_buff;
    uint32_t bits_len = 0;

    uint8_t nn[BYTECOUNT(p_bitcount/2)];
    memset(nn,0x00,sizeof(nn));

    vector_to_char_array(public_key.n,n_buff);
    BN_bin2bn(n_buff, public_key.n.size(), n);
    bits_len = BN_num_bits(n);
    BN_bn2binpad(n,nn,BYTECOUNT(p_bitcount/2));

    uint32_t r_len = 0;
    uint32_t m_len = 0;
    uint32_t nn_len = 0;

    nn_len = BYTECOUNT(bits_len);
    dev_alg_operation(operation_name,r,r_len,m,m_len,nn,nn_len,vec_size,p_bitcount,e_bitcount,output,output_len,m_flg,split_flg);
    BN_free(n);
    return status;
}

DEV_STATE Runtime::paillier_decrypt(uint8_t *ct,uint32_t vec_size,struct _private_key private_key,uint8_t *m_output,uint8_t *m_output_flg)
{
    bool split_flg = true;
    std::string  operation_name = "MOD_EXP_CONST_E";
    struct executor executor_dat;
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *lamda = BN_new();
    BN_CTX *bn_ctx  = BN_CTX_new();
    uint32_t p_bitcount = 2*private_key.n_bitcount;
    uint32_t e_bitcount = p_bitcount/2;
    uint8_t * p_buff;
    uint8_t * q_buff;
    vector_to_char_array(private_key.p,p_buff);
    BN_bin2bn(p_buff, private_key.p.size(), p);
    vector_to_char_array(private_key.q,q_buff);
    BN_bin2bn(q_buff, private_key.q.size(), q);
    BN_mul(n,p,q,bn_ctx);
    BN_sub(p, p,BN_value_one());
    BN_sub(q, q,BN_value_one());
    BN_mul(lamda,p,q,bn_ctx);

    uint32_t ct_len =  BYTECOUNT(p_bitcount)*vec_size;
    uint32_t bits_len=0;
    uint32_t lamba_byte_len =0;
    uint32_t n_len =0;

    bits_len = BN_num_bits(lamda);
    lamba_byte_len = BYTECOUNT(bits_len);
    uint8_t lamba_byte[lamba_byte_len];
    memset(lamba_byte,0x00,sizeof(lamba_byte));
    BN_bn2binpad(lamda,lamba_byte,lamba_byte_len);
    bits_len = BN_num_bits(n);
    n_len = BYTECOUNT(bits_len);
    uint8_t nn[n_len];
    memset(nn,0x00,sizeof(nn));
    BN_bn2binpad(n,nn,n_len);

    uint32_t output_len = 0;
    uint8_t *m1_output = new uint8_t[vec_size*BYTECOUNT(p_bitcount)];
    memset(m1_output,0x00,vec_size*BYTECOUNT(p_bitcount));

    std::vector<uint8_t > m_flg;
    dev_alg_operation(operation_name,ct,ct_len,lamba_byte,lamba_byte_len,nn,n_len,vec_size,p_bitcount,e_bitcount,m1_output,output_len,m_flg,split_flg);
    paillier_decrypt_step2(private_key,p_bitcount,vec_size,m1_output,output_len,m_output,m_output_flg);

    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(lamda);
    BN_CTX_free(bn_ctx);
    delete [] m1_output;
    return OK;
}

DEV_STATE Runtime::paillier_add(uint8_t *ct1,uint32_t ct1_len,uint8_t *ct2 ,uint32_t ct2_len,uint32_t vec_size,uint8_t *ct_output,uint32_t &output_len,struct _public_key public_key)
{
    DEV_STATE  status = OK;
    std::string  operation_name = "MOD_MUL";
    bool split_flg = true;
    uint32_t p_bitcount = 2*public_key.n_bitcount;
    uint32_t e_bitcount = p_bitcount/2;
    uint8_t * n_buff;
    uint32_t bits_len = 0;
    uint32_t nn_len = 0;

    BIGNUM *n = BN_new();
    vector_to_char_array(public_key.n,n_buff);
    BN_bin2bn(n_buff, public_key.n.size(), n);
    bits_len = BN_num_bits(n);
    nn_len = BYTECOUNT(bits_len);

    uint8_t nn[BYTECOUNT(p_bitcount/2)];
    memset(nn,0x00,sizeof(nn));
    BN_bn2binpad(n,nn,BYTECOUNT(p_bitcount/2));

    std::vector<uint8_t > m_flg;
    dev_alg_operation(operation_name,ct1,ct1_len,ct2,ct2_len,nn,nn_len,vec_size,p_bitcount,e_bitcount,ct_output,output_len,m_flg,split_flg);
    BN_free(n);
    return status;
}

DEV_STATE Runtime::paillier_mul(uint8_t *ct1,uint32_t ct1_len,uint8_t *m,uint32_t m_size,uint32_t vec_size,uint8_t *ct_output,uint32_t &output_len,struct _public_key public_key)
{
    DEV_STATE  status = OK;
    std::string  operation_name;
    bool split_flg = true;
    uint32_t m_len = 0;
    uint32_t nn_len = 0;
    if(m_size == 1)
    {
        operation_name = "MOD_EXP_CONST_E";
    }
    else
    {
        operation_name = "MOD_EXP";
    }
    
    uint32_t p_bitcount = 2*public_key.n_bitcount;
    uint32_t e_bitcount = p_bitcount/2;
    uint8_t * n_buff;
    uint32_t bits_len = 0;

    BIGNUM *n = BN_new();

    vector_to_char_array(public_key.n,n_buff);
    BN_bin2bn(n_buff, public_key.n.size(), n);
    bits_len = BN_num_bits(n);

    nn_len = BYTECOUNT(bits_len);

    uint8_t nn[nn_len];
    memset(nn,0x00,sizeof(nn));
    BN_bn2binpad(n,nn,nn_len);

    std::vector<uint8_t > m_flg;

    if(m_size == 1)
    {
        m_len = BYTECOUNT(e_bitcount);
        dev_alg_operation(operation_name,ct1,ct1_len,m,m_len,nn,nn_len,vec_size,p_bitcount,e_bitcount,ct_output,output_len,m_flg,split_flg);
    }
    else{
        uint32_t offset =0;
        m_len = m_size*BYTECOUNT(e_bitcount);
        for(uint32_t i=0;i<m_size;i++)
        {
            data_inverse(m+offset,BYTECOUNT(e_bitcount));
            offset +=BYTECOUNT(e_bitcount);
        }
        dev_alg_operation(operation_name,ct1,ct1_len,m,m_len,nn,nn_len,vec_size,p_bitcount,e_bitcount,ct_output,output_len,m_flg,split_flg);
    }
    
    BN_free(n);
    return status;
}

DEV_STATE Runtime::paillier_sub(uint8_t *ct1,uint32_t ct1_len,uint8_t *ct2,uint32_t ct2_len,uint32_t vec_size,uint8_t *ct_output,uint32_t &output_len,struct _public_key public_key)
{
    DEV_STATE  status = OK;
    std::string  operateion_name = "MOD_INV_CONST_P";
    uint32_t p_bitcount = 2*public_key.n_bitcount;
    uint32_t e_bitcount = p_bitcount/2;
    uint8_t * n_buff;
    uint32_t bits_len = 0;

    BIGNUM *n = BN_new();
    BIGNUM *n_squre = BN_new();
    BN_CTX *bn_ctx  = BN_CTX_new();

    vector_to_char_array(public_key.n,n_buff);
    BN_bin2bn(n_buff, public_key.n.size(), n);
    bits_len = BN_num_bits(n);
    BN_mul(n_squre,n,n,bn_ctx);

    uint8_t n_squre_byte[BYTECOUNT(p_bitcount)];
    uint32_t n_squre_offset = 0;

    uint8_t nn[BYTECOUNT(p_bitcount)];
    memset(nn,0x00,sizeof(nn));

    bits_len = BN_num_bits(n_squre);
    BN_bn2binpad(n_squre,n_squre_byte+n_squre_offset,BYTECOUNT(p_bitcount));
    bits_len = BN_num_bits(n);
    uint32_t nn_len = 0;
    nn_len = BYTECOUNT(bits_len);

    memset(nn,0x00,sizeof(nn));
    BN_bn2binpad(n,nn,nn_len);
    uint32_t split_flg = true;
    uint32_t n_squre_byte_len = BYTECOUNT(bits_len); 
    std::vector<uint8_t > m_flg;
    dev_alg_operation(operateion_name,ct2,ct2_len,n_squre_byte,n_squre_byte_len,nn,nn_len,vec_size,p_bitcount,e_bitcount,ct_output,output_len,m_flg,split_flg);
    operateion_name = "MOD_MUL";
    dev_alg_operation(operateion_name,ct1,ct1_len,ct_output,output_len,nn,nn_len,vec_size,p_bitcount,e_bitcount,ct_output,output_len,m_flg,split_flg);
    BN_free(n);
    BN_free(n_squre);
    BN_CTX_free(bn_ctx);
    return status;
}

}