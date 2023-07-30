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

#include "heu/library/algorithms/leichi_paillier/ciphertext.h"
#include <string_view>

namespace heu::lib::algorithms::leichi_paillier {

    std::string Ciphertext::ToString() const {
        char* str = BN_bn2dec(bn_);
        std::string result(str);
        return result;
    }

    Ciphertext& Ciphertext::operator=(const Ciphertext& other) {
        if (this != &other) {
            BN_copy(bn_, other.bn_);
        }
        return *this;
    }

    std::ostream &operator<<(std::ostream &os, const Ciphertext &ct) {
        char* str = BN_bn2dec(ct.bn_);
        os << str;
        return os;
    }

    bool Ciphertext::operator==(const Ciphertext &other) const {
        return (BN_cmp(bn_, other.bn_) == 0)?true:false;
    }

    bool Ciphertext::operator!=(const Ciphertext &other) const {
        return (BN_cmp(bn_, other.bn_) == 0)?true:false;        
    }

    yacl::Buffer Ciphertext::Serialize() const{
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
    void Ciphertext::Deserialize(yacl::ByteContainerView in){
        std::istringstream is((std::string)in);
        BN_bin2bn((uint8_t *)(is.str().data()), is.str().size()-1,bn_);
        int sign = in[is.str().size()-1]& 0x01 ? 1 : 0;
        BN_set_negative(bn_,sign);
    }

}  // namespace heu::lib::algorithms::leichi_paillier
