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
    class Plaintext {
        public:
            BIGNUM* bn_;
        public:
            Plaintext() {bn_ = BN_new();}
            ~Plaintext(){BN_free(bn_);}
            Plaintext(const Plaintext& other) {bn_ = BN_dup(other.bn_);}

            Plaintext operator-() const;
            Plaintext& operator=(const Plaintext& other);
            Plaintext operator*(const Plaintext& other) const;
            Plaintext operator+(const Plaintext& other) const;
            Plaintext operator-(const Plaintext &op2) const;
            Plaintext operator/(const Plaintext &op2) const;
            Plaintext operator%(const Plaintext &op2) const;

            static Plaintext generateRandom(const Plaintext &op2);

            BIGNUM* getValue() const {return bn_;}
            size_t numBits() const {return BN_num_bits(bn_);}
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

            template <typename T>
            explicit Plaintext(T &value) {
                Set(value);
            }

            template <typename T>
            void Set(T value);

            template <typename T>
            T Get() const;
            
            void Set(const std::string &num, int radix){BN_dec2bn(&bn_, num.c_str());}

            Plaintext Absolute(const Plaintext &pt);
            static void RandomExactBits(size_t bit_size, Plaintext *r);
            static void RandomLtN(const Plaintext &n, Plaintext *r);
            void NegateInplace();

            yacl::Buffer Serialize() const;
            void Deserialize(yacl::ByteContainerView buffer);

            yacl::Buffer ToBytes(size_t byte_len, Endian endian = Endian::native) const;
            void ToBytes(unsigned char *buf, size_t buf_len,
                        Endian endian = Endian::native) const;
    };

}