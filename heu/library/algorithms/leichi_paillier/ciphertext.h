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

#include "openssl/bn.h"
#include <ostream>
#include <string>
#include <utility>
#include "yacl/base/byte_container_view.h"
#include "cereal/archives/portable_binary.hpp"
#include <vector>
#pragma once
namespace heu::lib::algorithms::leichi_paillier {
    class Ciphertext {
        public:
            BIGNUM* bn_;
        public:
            Ciphertext() {
                bn_ = BN_new();
                }
            ~Ciphertext(){
                BN_free(bn_);
            } 

            Ciphertext(const Ciphertext& other) {
                bn_ = BN_dup(other.bn_);
            }

            Ciphertext& operator=(const Ciphertext& other) {
                if (this != &other) {
                    BN_copy(bn_, other.bn_);
                }
                return *this;
            }

            explicit Ciphertext(BIGNUM *bn){ bn_ = bn;}//BN_dup(bn);} 

            std::string ToString() const;
            friend std::ostream &operator<<(std::ostream &os, const Ciphertext &ct);

            bool operator==(const Ciphertext &other) const;
            bool operator!=(const Ciphertext &other) const;

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
            void Deserialize(yacl::ByteContainerView in){
                std::istringstream is((std::string)in);
                BN_bin2bn((uint8_t *)(is.str().data()), is.str().size(),bn_);
            }
    };
}// namespace heu::lib::algorithms::leichi_paillier