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
#include "heu/library/algorithms/util/spi_traits.h"
// #include "yacl/base/exception.h"
#include <ostream>
#include <string>
#include <utility>
#include "yacl/base/byte_container_view.h"
#include "cereal/archives/portable_binary.hpp"
#include <cstdint>
#include <iostream>
#include <vector>
#include <cmath>
#include <stdio.h>
#include "heu/library/algorithms/leichi_paillier/utils.h"

using int128_t = __int128_t;
using uint128_t = __uint128_t;
namespace heu::lib::algorithms::leichi_paillier {
    template <typename T>
        void ValueVecToPtsVec(std::vector<T>& value_vec, std::vector<T*>& pts_vec) {
        int size = value_vec.size();
        for (int i = 0; i < size; i++) {
            pts_vec.push_back(&value_vec[i]);
        }
    }

    class Plaintext {
        public:
            BIGNUM* bn_;
        public:
            Plaintext() {
                bn_ = BN_new();
            }
            ~Plaintext(){
                BN_free(bn_);
            }
            Plaintext(const Plaintext& other) {
                bn_ = BN_dup(other.bn_);
            }

            Plaintext operator-() const;

            Plaintext& operator=(const Plaintext& other) {
                if (this != &other) {
                    BN_copy(bn_, other.bn_);
                }
                return *this;
            }

            Plaintext operator*(const Plaintext& other) const {
                Plaintext result;
                BN_CTX *bn_ctx = BN_CTX_new();
                BN_mul(result.bn_, bn_, other.bn_, bn_ctx);
                BN_CTX_free(bn_ctx);
                return result;
            }

            Plaintext operator+(const Plaintext& other) const {
                Plaintext result;
                BN_add(result.bn_, bn_, other.bn_);
                return result;
            }

            Plaintext operator-(const Plaintext &op2) const {
                Plaintext result;
                BN_sub(result.bn_,bn_,op2.bn_);
                return result;
            }

            Plaintext operator/(const Plaintext &op2) const {
                Plaintext result;
                Plaintext rem;
                BN_CTX *bn_ctx      = BN_CTX_new();
                BN_div(result.bn_,rem.bn_,bn_,op2.bn_,bn_ctx);
                BN_CTX_free(bn_ctx);
                return result;
            }

            Plaintext operator%(const Plaintext &op2) const {
                Plaintext result;
                BN_CTX *bn_ctx      = BN_CTX_new();
                BN_mod(result.bn_,bn_,op2.bn_,bn_ctx);
                BN_CTX_free(bn_ctx);
                return result;
            }

            static Plaintext generateRandom(const Plaintext &op2) {
                Plaintext randomNum;
                BN_rand_range(randomNum.bn_, op2.bn_);
                return randomNum;
            }

            BIGNUM* getValue() const {
                return bn_;
            }

            size_t numBits() const {
                return BN_num_bits(bn_);
            }

            friend std::ostream &operator<<(std::ostream &os, const Plaintext &pt);

            Plaintext operator&(const Plaintext &op2) const;
            Plaintext operator|(const Plaintext &op2) const;
            Plaintext operator^(const Plaintext &op2) const;
            Plaintext operator<<(size_t op2) const;
            Plaintext operator>>(size_t op2) const;

            Plaintext operator+=(const Plaintext &op2);
            Plaintext operator-=(const Plaintext &op2);
            Plaintext operator*=(const Plaintext &op2);
            Plaintext operator/=(const Plaintext &op2);
            Plaintext operator%=(const Plaintext &op2);
            Plaintext operator&=(const Plaintext &op2);
            Plaintext operator|=(const Plaintext &op2);
            Plaintext operator^=(const Plaintext &op2);
            Plaintext operator<<=(size_t op2);
            Plaintext operator>>=(size_t op2);
            
            bool IsZero() const{return BN_is_zero(bn_);}      
            bool IsPositive() const{return (BN_is_negative(bn_) == 0 && !BN_is_zero(bn_))?true:false;}  
            bool IsNegative() const{return (BN_is_negative(bn_) == 1)?true:false;}  
            size_t BitCount() const { return BN_num_bits(bn_); }
            bool operator!=(const Plaintext &other) const;
            bool operator>(const Plaintext &other) const{return (BN_cmp(bn_, other.bn_) > 0)?true:false;}
            bool operator<(const Plaintext &other) const{return (BN_cmp(bn_, other.bn_) < 0)?true:false;}
            bool operator>=(const Plaintext &other) const{return (BN_cmp(bn_, other.bn_) >= 0)?true:false;}
            bool operator<=(const Plaintext &other) const{return (BN_cmp(bn_, other.bn_) <= 0)?true:false;}
            bool operator==(const Plaintext &other) const{return (BN_cmp(bn_, other.bn_) == 0)?true:false;}

            std::string ToHexString() const;
            std::string ToString() const;

            Plaintext get_prime(size_t bit_len){
                Plaintext result;
                BN_generate_prime_ex(result.bn_,bit_len,1,NULL,NULL,NULL);
                return result;
            }

            void get_prime(size_t bit_len,const Plaintext &op)
            {
                BN_generate_prime_ex(op.bn_,bit_len,1,NULL,NULL,NULL);
            }

            template <typename T>
            explicit Plaintext(T &value) {
                Set(value);
            }

            template <typename T>
            void Set(T value);

            template <typename T>
            T Get() const;
            
            void Set(const std::string &num, int radix){BN_dec2bn(&bn_, num.c_str());}

            Plaintext Absolute(const Plaintext &pt){
                Plaintext result;
                BN_copy(result.bn_,bn_);
                BN_set_negative(bn_, 0);
                return result;
            }

            static void RandomExactBits(size_t bit_size, Plaintext *r);
            static void RandomLtN(const Plaintext &n, Plaintext *r);
            void NegateInplace();

            yacl::Buffer Serialize() const{
                uint32_t n_bits_len = BN_num_bits(bn_);
                uint8_t* n_arr = new uint8_t[n_bits_len];
                std::vector<uint8_t> vec_tmp;
                BN_bn2bin(bn_, n_arr);
                uint32_t bytes_len = std::ceil(n_bits_len/8.0);
                for(uint32_t i=0;i<bytes_len;i++)
                {
                    vec_tmp.push_back(n_arr[i]);
                }
                yacl::Buffer buf(vec_tmp.data(), std::ceil(BN_num_bits(bn_)/8.0));
                return buf;
            }
            void Deserialize(yacl::ByteContainerView buffer){
                std::istringstream is((std::string)buffer);
                BN_bin2bn((uint8_t *)(is.str().data()), is.str().size(),bn_);
                BN_set_negative(bn_,1);
            }

            yacl::Buffer ToBytes(size_t byte_len, Endian endian = Endian::native) const{yacl::Buffer buf(byte_len);return buf;}
            void ToBytes(unsigned char *buf, size_t buf_len,
                        Endian endian = Endian::native) const{}
    };

}