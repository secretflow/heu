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

            yacl::Buffer Serialize() const;
            void Deserialize(yacl::ByteContainerView in);
    };

}  // namespace heu::lib::algorithms::leichi_paillier

