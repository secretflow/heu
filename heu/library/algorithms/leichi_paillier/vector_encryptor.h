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

#pragma once
#include "heu/library/algorithms/leichi_paillier/ciphertext.h"
#include "heu/library/algorithms/leichi_paillier/plaintext.h"
#include "heu/library/algorithms/leichi_paillier/public_key.h"
#include "heu/library/algorithms/leichi_paillier/utils.h"
namespace heu::lib::algorithms::leichi_paillier {
        class Encryptor {
            public:
            explicit Encryptor(const PublicKey& pk): pk_(std::move(pk)){max_plaintext = pk.max_plaintext_;}
            std::vector<Ciphertext> EncryptZero(int64_t size) const;
            std::vector<Ciphertext> Encrypt(ConstSpan<Plaintext> pts) const;
            std::pair<std::vector<Ciphertext>, std::vector<std::string>> EncryptWithAudit(
                ConstSpan<Plaintext> pts) const{YACL_THROW("Not Implemented.");};
         private:
            PublicKey pk_;
            Plaintext max_plaintext;
    };
}
