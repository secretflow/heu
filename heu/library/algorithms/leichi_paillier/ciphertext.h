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

            yacl::Buffer Serialize() const;
            // void Deserialize(yacl::ByteContainerView in);
            void Deserialize(const yacl::ByteContainerView& buffer);

        private:
            template <class Archive>
            static void SerializeBignum(Archive& archive, const BIGNUM* bn) {
                char* bn_str = BN_bn2hex(bn);
                archive(cereal::make_size_tag(static_cast<uint32_t>(strlen(bn_str))));
                archive(cereal::binary_data(bn_str, static_cast<std::size_t>(strlen(bn_str))));
            }
        };
}// namespace heu::lib::algorithms::leichi_paillier