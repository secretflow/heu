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

#include "heu/library/algorithms/leichi_paillier/key_generator.h"
#include <ostream>
#include <string>
#include <utility>
#include <cstdint>
#include <iostream>
namespace heu::lib::algorithms::leichi_paillier {
    void get_prime(size_t bit_len,const Plaintext &op)
    {
        BN_generate_prime_ex(op.bn_,bit_len,1,NULL,NULL,NULL);
    }
    void KeyGenerator::Generate(size_t key_size, SecretKey* sk, PublicKey* pk){
        do{
            get_prime(key_size/2,sk->p_);
            get_prime(key_size/2,sk->q_);
        }while(sk->p_ == sk->q_);

        pk->n_ = sk->p_*sk->q_;
        Plaintext one;
        uint32_t a =1;
        one.Set(a);
        pk->g_ = pk->n_ + one;
        pk->max_plaintext_ = pk->n_;
    }

    void KeyGenerator::Generate(SecretKey* sk, PublicKey* pk) {
        Generate(2048, sk, pk);
    }
}