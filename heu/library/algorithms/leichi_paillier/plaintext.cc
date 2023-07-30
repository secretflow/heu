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
#include "heu/library/algorithms/leichi_paillier/utils.h"
namespace heu::lib::algorithms::leichi_paillier {
    void vector_to_char_array(std::vector<uint8_t>& vec, unsigned char* &arr) 
    {
        arr = reinterpret_cast<unsigned char*>(vec.data());
    }

    Plaintext& Plaintext::operator=(const Plaintext& other) {
        if (this != &other) {
            BN_copy(bn_, other.bn_);
        }
        return *this;
    }

    Plaintext Plaintext::operator*(const Plaintext& other) const {
        Plaintext result;
        BN_CTX *bn_ctx = BN_CTX_new();
        BN_mul(result.bn_, bn_, other.bn_, bn_ctx);
        BN_CTX_free(bn_ctx);
        return result;
    }

    Plaintext Plaintext::operator+(const Plaintext& other) const {
        Plaintext result;
        BN_add(result.bn_, bn_, other.bn_);
        return result;
    }

    Plaintext Plaintext::operator-(const Plaintext &op2) const {
        Plaintext result;
        BN_sub(result.bn_,bn_,op2.bn_);
        return result;
    }

    Plaintext Plaintext::operator-() const{
        Plaintext result;
        BN_copy(result.bn_,bn_);
        BN_set_negative(result.bn_,!BN_is_negative(bn_));
        return result;
    }

    Plaintext Plaintext::operator/(const Plaintext &op2) const {
        Plaintext result;
        Plaintext rem;
        BN_CTX *bn_ctx      = BN_CTX_new();
        BN_div(result.bn_,rem.bn_,bn_,op2.bn_,bn_ctx);
        BN_CTX_free(bn_ctx);
        return result;
    }

    Plaintext Plaintext::operator%(const Plaintext &op2) const {
        Plaintext result;
        BN_CTX *bn_ctx      = BN_CTX_new();
        BN_mod(result.bn_,bn_,op2.bn_,bn_ctx);
        BN_CTX_free(bn_ctx);
        return result;
    }

    std::ostream& operator<<(std::ostream& os, const Plaintext& pt) {
        char* str = BN_bn2dec(pt.bn_);
        os << str;
        return os;
    }
    bool Plaintext::operator!=(const Plaintext& other) const {
        return (BN_cmp(bn_, other.bn_))?true:false;
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
    
    template <>
    void Plaintext::Set(Plaintext value) {
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
        uint128_t avalue = value > 0 ? value : -value;
        auto sign = value > 0 ? 0 : 1;
        unsigned char data[16] = {0}; 
        for (size_t i = 0; i < sizeof(value); ++i) {
            data[sizeof(value) - i - 1] = (unsigned char)(avalue >> (i * 8));
        }
        bn_ = BN_bin2bn(data, sizeof(data), NULL);
        BN_set_negative(bn_,sign);
    }

    template <>
    void Plaintext::Set(uint128_t value) {
        unsigned char data[16] = {0}; 
        for (size_t i = 0; i < sizeof(value); ++i) {
            data[sizeof(value) - i - 1] = (unsigned char)(value >> (i * 8));
        }

        bn_ = BN_bin2bn(data, sizeof(data), NULL);
    }

    template <>
    BIGNUM * Plaintext::Get() const{
        return bn_;
    }

    template <>
    int8_t Plaintext::Get() const{
        int8_t value = 0;
        if(BN_is_negative(bn_))
        {
            BN_set_negative(bn_,1);
        }
        value = BN_get_word(bn_);
        return value;
    }

    template <>
    uint8_t Plaintext::Get() const{
        uint8_t value = 0;
        value = BN_get_word(bn_);
        return value;
    }

    template <>
    int16_t Plaintext::Get() const{
        char *str = BN_bn2dec(bn_);
        int16_t value = (int16_t)strtol(str, NULL, 10);
        return value;
    }

    template <>
    uint16_t Plaintext::Get() const{
        uint16_t value = 0;
        value = BN_get_word(bn_);
        return value;
    }

    template <>
    int32_t Plaintext::Get() const{
        char *str = BN_bn2dec(bn_);
        int32_t value = (int32_t)strtol(str, NULL, 10);
        return value;
    }

    template <>
    uint32_t Plaintext::Get() const{
        uint32_t value = 0;
        value = BN_get_word(bn_);
        return value;
    }

    template <>
    int64_t Plaintext::Get() const{
        char *str = BN_bn2dec(bn_);
        int64_t value = (int64_t)strtol(str, NULL, 10);
        return value;
    }

    template <>
    uint64_t Plaintext::Get() const{
        uint64_t value = 0;
        value = BN_get_word(bn_);
        return value;
    }

    template <>
    int128_t Plaintext::Get() const{
        std::vector<uint8_t> vec_tmp;
        uint8_t * _buff;
        int128_t value = 0;
        vec_tmp = bnTobin(this->bn_);
        std::reverse(vec_tmp.begin(), vec_tmp.end());
        vector_to_char_array(vec_tmp,_buff);
        std::memcpy(&value,_buff,vec_tmp.size());

        if(BN_is_negative(bn_))
        {
            value = -value;
        }
        return value;
    }

    template <>
    uint128_t Plaintext::Get() const{
        std::vector<uint8_t> vec_tmp;
        uint8_t * _buff;
        uint128_t value = 0;
        vec_tmp = bnTobin(this->bn_);
        std::reverse(vec_tmp.begin(), vec_tmp.end());
        vector_to_char_array(vec_tmp,_buff);
        std::memcpy(&value,_buff,vec_tmp.size());
        return value;
    }

    template <>
    void Plaintext::Set(double value) {
        int64_t int_val = static_cast<int64_t>(value);
        Set(int_val);
    }

    template <>
    double Plaintext::Get() const {
        int64_t ret = this->Get<int64_t>();
        return (double)ret;
    }

    template <>
    void Plaintext::Set(float value) {
        int64_t int_val = static_cast<int64_t>(value);
        Set(int_val);
    }

    template <>
    float Plaintext::Get() const {
        int64_t ret = this->Get<int64_t>();
        return (float)ret;
    }

    Plaintext Plaintext::generateRandom(const Plaintext &op2) {
        Plaintext randomNum;
        BN_rand_range(randomNum.bn_, op2.bn_);
        return randomNum;
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
        std::vector<uint8_t> a_vec;
        std::vector<uint8_t> b_vec;
        std::vector<uint8_t> c_vec;

        bool is_res_negtive;
        if ((this->IsNegative() && !op2.IsNegative()) ||
            (!this->IsNegative() && op2.IsNegative())) {
            is_res_negtive = true;
        } else {
            is_res_negtive = false;
        }

        a_vec = bnTobin(bn_);
        b_vec = bnTobin(op2.bn_);

        int size = std::max(a_vec.size(), b_vec.size());

        for (int i = 0; i < size; i++)
        {
            c_vec.push_back(a_vec[i] & b_vec[i]);
        }
        uint8_t * _buff;
        vector_to_char_array(c_vec,_buff);
        BN_bin2bn(_buff, c_vec.size(),result.bn_);
        if(is_res_negtive)
        {
            BN_set_negative(result.bn_,1);
        }
        return result;
    }
    Plaintext Plaintext::operator|(const Plaintext &op2) const
    {
        Plaintext result;

        std::vector<uint8_t> a_vec;
        std::vector<uint8_t> b_vec;
        std::vector<uint8_t> c_vec;

        bool is_res_negtive;
        if ((this->IsNegative() && !op2.IsNegative()) ||
            (!this->IsNegative() && op2.IsNegative())) {
            is_res_negtive = true;
        } else {
            is_res_negtive = false;
        }
        a_vec = bnTobin(bn_);
        b_vec = bnTobin(op2.bn_);

        int size = std::max(a_vec.size(), b_vec.size());

        for (int i = 0; i < size; i++)
        {
            c_vec.push_back(a_vec[i] | b_vec[i]);
        }
        uint8_t * _buff;
        vector_to_char_array(c_vec,_buff);
        BN_bin2bn(_buff, c_vec.size(),result.bn_);
        if(is_res_negtive)
        {
            BN_set_negative(result.bn_,1);
        }
        return result;
    }
    Plaintext Plaintext::operator^(const Plaintext &op2) const
    {
        Plaintext result;
        std::vector<uint8_t> a_vec;
        std::vector<uint8_t> b_vec;
        std::vector<uint8_t> c_vec;

        bool is_res_negtive;
        if ((this->IsNegative() && !op2.IsNegative()) ||
            (!this->IsNegative() && op2.IsNegative())) {
            is_res_negtive = true;
        } else {
            is_res_negtive = false;
        }
        a_vec = bnTobin(bn_);
        b_vec = bnTobin(op2.bn_);

        int size = std::max(a_vec.size(), b_vec.size());

        for (int i = 0; i < size; i++)
        {
            c_vec.push_back(a_vec[i] ^ b_vec[i]);
        }

        uint8_t * _buff;
        vector_to_char_array(c_vec,_buff);
        BN_bin2bn(_buff, c_vec.size(),result.bn_);
        if(is_res_negtive)
        {
            BN_set_negative(result.bn_,1);
        }
        return result;
    }
    Plaintext Plaintext::operator<<(size_t op2) const
    {
        Plaintext result;
        BN_lshift(result.bn_,bn_,op2);
        return result;
    }
    Plaintext Plaintext::operator>>(size_t op2) const
    {    
        Plaintext result;
        BN_rshift(result.bn_,bn_,op2);
        return result;
    }

    Plaintext Plaintext::operator&=(const Plaintext &op2)
    {
        std::vector<uint8_t> a_vec;
        std::vector<uint8_t> b_vec;
        std::vector<uint8_t> c_vec;

        bool is_res_negtive;
        if ((this->IsNegative() && !op2.IsNegative()) ||
            (!this->IsNegative() && op2.IsNegative())) {
            is_res_negtive = true;
        } else {
            is_res_negtive = false;
        }

        a_vec = bnTobin(bn_);
        std::reverse(a_vec.begin(), a_vec.end());
        b_vec = bnTobin(op2.bn_);
        std::reverse(b_vec.begin(), b_vec.end());

        int size = std::max(a_vec.size(), b_vec.size());
        
        for (int i = 0; i < size; i++)
        {
            a_vec[i] = ((size_t)i < a_vec.size()) ? a_vec[i] : (uint32_t)0;
            a_vec[i] &= b_vec[i];
            c_vec.push_back(a_vec[i]);
        }
        
        std::reverse(c_vec.begin(), c_vec.end());
        uint8_t * _buff;
        vector_to_char_array(c_vec,_buff);
        BN_bin2bn(_buff, c_vec.size(),this->bn_);
        if(is_res_negtive)
        {
            BN_set_negative(this->bn_,1);
        }
        return *this;
    }

    Plaintext Plaintext::operator|=(const Plaintext &op2)
    {
        std::vector<uint8_t> a_vec;
        std::vector<uint8_t> b_vec;
        std::vector<uint8_t> c_vec;

        bool is_res_negtive;
        if ((this->IsNegative() && !op2.IsNegative()) ||
            (!this->IsNegative() && op2.IsNegative())) {
            is_res_negtive = true;
        } else {
            is_res_negtive = false;
        }

        a_vec = bnTobin(bn_);
        std::reverse(a_vec.begin(), a_vec.end());
        b_vec = bnTobin(op2.bn_);
        std::reverse(b_vec.begin(), b_vec.end());

        int size = std::max(a_vec.size(), b_vec.size());

        for (int i = 0; i < size; i++)
        {
            a_vec[i] = ((size_t)i < a_vec.size()) ? a_vec[i] : (uint32_t)0;
            a_vec[i] |= b_vec[i];
            c_vec.push_back(a_vec[i]);
        }
        std::reverse(c_vec.begin(), c_vec.end());

        uint8_t * _buff;
        vector_to_char_array(c_vec,_buff);
        BN_bin2bn(_buff, c_vec.size(),this->bn_);
        if(is_res_negtive)
        {
            BN_set_negative(this->bn_,1);
        }
        return *this;
    }
    Plaintext Plaintext::operator^=(const Plaintext &op2)
    {
        std::vector<uint8_t> a_vec;
        std::vector<uint8_t> b_vec;
        std::vector<uint8_t> c_vec;

        bool is_res_negtive;
        if ((this->IsNegative() && !op2.IsNegative()) ||
            (!this->IsNegative() && op2.IsNegative())) {
            is_res_negtive = true;
        } else {
            is_res_negtive = false;
        }
        a_vec = bnTobin(bn_);
        std::reverse(a_vec.begin(), a_vec.end());
        b_vec = bnTobin(op2.bn_);
        std::reverse(b_vec.begin(), b_vec.end());

        int size = std::max(a_vec.size(), b_vec.size());

        for (int i = 0; i < size; i++)
        {
            a_vec[i] = ((size_t)i < a_vec.size()) ? a_vec[i] : (uint32_t)0;
            a_vec[i] ^= b_vec[i];
            c_vec.push_back(a_vec[i]);
        }
        std::reverse(c_vec.begin(), c_vec.end());
        uint8_t * _buff;
        vector_to_char_array(c_vec,_buff);
        BN_bin2bn(_buff, c_vec.size(),this->bn_);
        if(is_res_negtive)
        {
            BN_set_negative(this->bn_,1);
        }
        return *this;
    }
    Plaintext Plaintext::operator<<=(size_t op2)
    {
        BN_lshift(bn_,bn_,op2);
        return *this;
    }
    Plaintext Plaintext::operator>>=(size_t op2)
    {   
        BN_rshift(bn_,bn_,op2);
        return *this;
    }

    void Plaintext::NegateInplace(){
        if(BN_is_negative(bn_))
        {
            BN_set_negative(bn_,0);
        }
        else{
            BN_set_negative(bn_,1);
        }
        // *this = -(*this); 
    }

    Plaintext Plaintext::Absolute(const Plaintext &pt){
        Plaintext result;
        BN_copy(result.bn_,bn_);
        BN_set_negative(bn_, 0);
        return result;
    }

    yacl::Buffer Plaintext::Serialize() const{
        uint32_t n_bits_len = BN_num_bits(bn_);
        uint8_t* n_arr = new uint8_t[n_bits_len];
        std::vector<uint8_t> vec_tmp;
        BN_bn2bin(bn_, n_arr);
        uint32_t bytes_len = std::ceil(n_bits_len/8.0);
        for(uint32_t i=0;i<bytes_len;i++)
        {
            vec_tmp.push_back(n_arr[i]);
        }
        uint8_t sign = BN_is_negative(bn_) ? 1 : 0;
        vec_tmp.push_back(sign);
        yacl::Buffer buf(vec_tmp.data(), std::ceil(BN_num_bits(bn_)/8.0)+1);
        return buf;
    }
    void Plaintext::Deserialize(yacl::ByteContainerView buffer){
        
        std::istringstream is((std::string)buffer);
        BN_bin2bn((uint8_t *)(is.str().data()), is.str().size()-1,bn_);
        int sign = buffer[is.str().size()-1]& 0x01 ? 1 : 0;
        BN_set_negative(bn_,sign);
    }

    yacl::Buffer Plaintext::ToBytes(size_t byte_len, Endian endian) const{
        yacl::Buffer buf(byte_len);
        ToBytes(buf.data<uint8_t>(), byte_len, endian);
        return buf;
    }
    void Plaintext::ToBytes(unsigned char *buf, size_t buf_len,
                Endian endian) const{
        std::vector<uint8_t> vec_tmp;
        uint32_t n_bits_len = BN_num_bits(bn_);
        uint8_t* n_arr = new uint8_t[n_bits_len];
        BN_bn2bin(bn_, n_arr);
        uint32_t bytes_len = std::ceil(n_bits_len/8.0);
        for(uint32_t i=0;i<bytes_len;i++)
        {
            vec_tmp.push_back(n_arr[i]);
        }
        if (endian == Endian::big) {
            ;
        } else {
            std::reverse(vec_tmp.begin(), vec_tmp.end());
        }
    }
}