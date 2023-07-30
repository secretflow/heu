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
#include "heu/library/algorithms/util/he_object.h"
#include "openssl/bn.h"
#include "heu/library/algorithms/leichi_paillier/plaintext.h"
namespace heu::lib::algorithms::leichi_paillier {
    class SecretKey  {
        public:
            Plaintext p_, q_;   
            bool operator==(const SecretKey &other) const {
                return p_ == other.p_ && q_ == other.q_ ;
            }

            bool operator!=(const SecretKey &other) const {
                return !this->operator==(other);
            }

            [[nodiscard]] std::string ToString() const {
                return fmt::format("leichi_paillier SK, p={}[{}bits], q={}[{}bits]", p_.ToHexString(),
                                p_.BitCount(), q_.ToHexString(), q_.BitCount());
            }

            yacl::Buffer Serialize() const { YACL_THROW("Not implemented."); }
            void Deserialize(yacl::ByteContainerView in) {
                YACL_THROW("Not implemented.");
            }
    };

}

