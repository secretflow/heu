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

#include "heu/library/algorithms/leichi_paillier/plaintext.h"
#include "cereal/archives/portable_binary.hpp"
namespace heu::lib::algorithms::leichi_paillier {
    std::string to_string(uint128_t x)
    {
        if (x == 0) return "0";
        std::string s = "";
        while (x > 0) {
            s += char(x % 10 + '0');
            x /= 10;
        }
        reverse(s.begin(), s.end());
        return s;
    }

    std::ostream& operator<<(std::ostream& os, const Plaintext& pt) {
        char* str = BN_bn2dec(pt.bn_);
        os << str;
        return os;
    }
    bool Plaintext::operator!=(const Plaintext& other) const {
        return (BN_cmp(bn_, other.bn_) == 0)?true:false;
    }

    std::string Plaintext::ToString() const {
        char* str = BN_bn2dec(bn_);
        std::string result(str);
        return result;
    }

    std::string Plaintext::ToHexString() const {
        char* str = BN_bn2hex(bn_);
        std::string result(str);
        return result;
    }
    
    Plaintext Plaintext::operator-() const{
        Plaintext result;
        BN_copy(result.bn_,bn_);
        BN_set_negative(result.bn_,!BN_is_negative(bn_));
        return result;
    }

    template <>
    void Plaintext::Set(Plaintext value) {
        // bn_ = value.bn_;
        bn_ = BN_dup(value.bn_);
    }


    template <>
    void Plaintext::Set(uint8_t value) {
        BN_set_word(bn_,(BN_ULONG)value);
    }

    template <>
    void Plaintext::Set(int8_t value) {
        BN_set_word(bn_,(BN_ULONG)abs(value));
        if(value < 0)
        {
            BN_set_negative(bn_,1);
        } 
    }

    template <>
    void Plaintext::Set(uint16_t value) {
        BN_set_word(bn_,(BN_ULONG)value);
    }

    template <>
    void Plaintext::Set(int16_t value) {
        BN_set_word(bn_,(BN_ULONG)abs(value));
        if(value < 0)
        {
            BN_set_negative(bn_,1);
        } 
    }

    template <>
    void Plaintext::Set(uint32_t value) {
        BN_set_word(bn_,(BN_ULONG)value);
    }

    template <>
    void Plaintext::Set(int32_t value) {
        BN_set_word(bn_,(BN_ULONG)abs(value));
        if(value < 0)
        {
            BN_set_negative(bn_,1);
        } 
    }

    template <>
    void Plaintext::Set(int64_t value) {
        BN_set_word(bn_,(BN_ULONG)abs(value));
        if(value < 0){
            BN_set_negative(bn_,1);
        }
    }

    template <>
    void Plaintext::Set(uint64_t value) {
        BN_set_word(bn_,(BN_ULONG)value);
    }

    template <>
    void Plaintext::Set(int128_t value) {
        // int len = sizeof(value);
        // std::cout<<to_string(value)<<std::endl;
        // BN_bin2bn((const uint8_t *)&value,64,bn_);
        BN_set_word(bn_, value);
    }

    template <>
    void Plaintext::Set(uint128_t value) {
        // int len = sizeof(value);
        // std::cout<<to_string(value)<<std::endl;
        // BN_bin2bn((const uint8_t *)&value,len,bn_);
        BN_set_word(bn_, value);
    }

    template <>
    BIGNUM * Plaintext::Get() const{
        return bn_;
    }

    template <>
    uint32_t Plaintext::Get() const{
        uint32_t value = 0;
        value = BN_get_word(bn_);
        return value;
    }

    void Plaintext::RandomExactBits(size_t bit_size, Plaintext *r){
        BN_rand(r->bn_,bit_size,0,0);
    }

    void Plaintext::RandomLtN(const Plaintext &n, Plaintext *r){
        BN_rand_range(r->bn_, n.bn_);
    }

    Plaintext Plaintext::operator+=(const Plaintext &op2) {
        BN_add(bn_,bn_,op2.bn_);
        return *this;
    }

    Plaintext Plaintext::operator-=(const Plaintext &op2) {
        BN_sub(bn_,bn_,op2.bn_);
        return *this;
    }

    Plaintext Plaintext::operator*=(const Plaintext &op2) {
        BN_CTX *bn_ctx      = BN_CTX_new();
        BN_mul(bn_,bn_,op2.bn_,bn_ctx);
        BN_CTX_free(bn_ctx);
        return *this;
    }

    Plaintext Plaintext::operator/=(const Plaintext &op2) {
        Plaintext rem;
        BN_CTX *bn_ctx      = BN_CTX_new();
        BN_div(bn_,rem.bn_,bn_,op2.bn_,bn_ctx);
        BN_CTX_free(bn_ctx);
        return *this;
    }

    Plaintext Plaintext::operator%=(const Plaintext &op2) {
        BN_CTX *bn_ctx      = BN_CTX_new();
        BN_mod(bn_,bn_,op2.bn_,bn_ctx);
        BN_CTX_free(bn_ctx);
        return *this;
    }

    Plaintext Plaintext::operator&(const Plaintext &op2) const
    {
        Plaintext result;
        return result;
    }
    Plaintext Plaintext::operator|(const Plaintext &op2) const
    {
        Plaintext result;
        return result;
    }
    Plaintext Plaintext::operator^(const Plaintext &op2) const
    {
        Plaintext result;
        return result;
    }
    Plaintext Plaintext::operator<<(size_t op2) const
    {
        Plaintext result;
        return result;
    }
    Plaintext Plaintext::operator>>(size_t op2) const
    {
        Plaintext result;
        return result;
    }

    Plaintext Plaintext::operator|=(const Plaintext &op2)
    {
        Plaintext result;
        return result;
    }
    Plaintext Plaintext::operator^=(const Plaintext &op2)
    {
        Plaintext result;
        return result;
    }
    Plaintext Plaintext::operator<<=(size_t op2)
    {
        Plaintext result;
        return result;
    }
    Plaintext Plaintext::operator>>=(size_t op2)
    {   
        Plaintext result;
        return result;
    }

    Plaintext Plaintext::operator&=(const Plaintext &op2)
    {
        Plaintext result;
        return result;
    }
    void Plaintext::NegateInplace(){

    }
}