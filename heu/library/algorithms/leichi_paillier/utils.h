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
#include "openssl/bn.h"
#include "heu/library/algorithms/leichi_paillier/plaintext.h"
#include "heu/library/algorithms/leichi_paillier/ciphertext.h"
namespace heu::lib::algorithms::leichi_paillier {
    template <typename T>
    std::vector<uint8_t> Tobin(T &op)
    {
        uint32_t n_bits_len = op.numBits();
        uint8_t* n_arr = new uint8_t[n_bits_len];
        std::vector<uint8_t> vec_tmp;
        BN_bn2bin(op.bn_, n_arr);
        uint32_t bytes_len = ((n_bits_len)>>3);
        for(uint32_t i=0;i<bytes_len;i++)
        {
            vec_tmp.push_back(n_arr[i]);
        }
        delete[] n_arr;
        return vec_tmp;
    }

}