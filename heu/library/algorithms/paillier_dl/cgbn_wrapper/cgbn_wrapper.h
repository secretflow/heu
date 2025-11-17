// Copyright 2023 Denglin Co., Ltd.
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

#include <vector>
#include "heu/library/algorithms/paillier_dl/ciphertext.h"
#include "heu/library/algorithms/paillier_dl/public_key.h"
#include "heu/library/algorithms/paillier_dl/secret_key.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_dl {

class PublicKey;
class SecretKey;
class Ciphertext;

class CGBNWrapper {
    public:
        static void InitSK(SecretKey *sk);
        static void InitPK(PublicKey *pk);
        static void Encrypt(const std::vector<Plaintext>& pts, const PublicKey& pk, std::vector<Ciphertext>* cts);
        static void Decrypt(const std::vector<Ciphertext>& cts, const SecretKey& sk, const PublicKey& pk, std::vector<Plaintext>* pts);
        static void Add(const PublicKey& pk, const std::vector<Ciphertext>& as, const std::vector<Ciphertext>& bs, std::vector<Ciphertext>* cs);
        static void Add(const PublicKey& pk, const std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs, std::vector<Ciphertext>* cs);
        static void Mul(const PublicKey& pk, const std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs, std::vector<Ciphertext>* cs);
        static void Negate(const PublicKey& pk, const std::vector<Ciphertext>& as, std::vector<Ciphertext>* cs);
        static void DevMalloc(PublicKey *pk);
        static void DevMalloc(SecretKey *sk);
        static void DevFree(PublicKey *pk);
        static void DevFree(SecretKey *sk);
        static void DevCopy(PublicKey *dst_pk, const PublicKey& pk);
        static void DevCopy(SecretKey *dst_sk, const SecretKey& sk);
        static void StoreToDev(PublicKey *pk);
        static void StoreToDev(SecretKey *sk);
        static void StoreToHost(PublicKey *pk);
        static void StoreToHost(SecretKey *sk);
};

} // namespace heu::lib::algorithms::paillier_dl