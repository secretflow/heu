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

#include "openssl/bn.h"
#include "heu/library/algorithms/leichi_paillier/plaintext.h"
#pragma once
namespace heu::lib::algorithms::leichi_paillier {

    void SetCacheTableDensity(size_t density);

    class PublicKey  {
        public:
            Plaintext n_;     
            Plaintext g_;  
            Plaintext max_plaintext_;

            void Init();
            [[nodiscard]] std::string ToString() const;

            bool operator==(const PublicKey &other) const {
                return (n_ == other.n_)?true:false ;
            }

            bool operator!=(const PublicKey &other) const {
                return (!this->operator==(other))?true:false;
            }

            [[nodiscard]] const Plaintext &PlaintextBound() const & { return max_plaintext_; }

            yacl::Buffer Serialize() const{  
                uint32_t n_bits_len = BN_num_bits(n_.bn_);
                uint8_t* n_arr = new uint8_t[n_bits_len];
                std::vector<uint8_t> vec_tmp;
                BN_bn2bin(n_.bn_, n_arr);
                uint32_t bytes_len = std::ceil(n_bits_len/8.0);
                for(uint32_t i=0;i<bytes_len;i++)
                {
                    vec_tmp.push_back(n_arr[i]);
                }
                yacl::Buffer buf(vec_tmp.data(), std::ceil(BN_num_bits(n_.bn_)/8.0));
                return buf;
            };
            void Deserialize(yacl::ByteContainerView in){
                std::istringstream is((std::string)in);
                BN_bin2bn((uint8_t *)(is.str().data()), is.str().size(),n_.bn_);
            };
    };

}  // namespace heu::lib::algorithms::leichi_paillier

