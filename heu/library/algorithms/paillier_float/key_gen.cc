// Copyright 2022 Ant Group Co., Ltd.
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

#include "heu/library/algorithms/paillier_float/key_gen.h"

#include "spdlog/spdlog.h"

#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::paillier_f {

void KeyGenerator::Generate(size_t key_bits, SecretKey* sk, PublicKey* pk) {
  MPInt p;
  MPInt q;
  MPInt n;

  size_t n_len = 0;
  while (n_len != key_bits) {
    SPDLOG_DEBUG("generate random prime p");
    MPInt::RandPrimeOver(key_bits / 2, &p);
    do {
      MPInt::RandPrimeOver(key_bits / 2, &q);
      SPDLOG_DEBUG("generate random prime p");
    } while (p.Compare(q) == 0);
    MPInt::Mul(p, q, &n);
    n_len = n.BitCount();
  }

  SPDLOG_DEBUG("success generate n = p*q");

  *pk = PublicKey(std::move(n));
  SPDLOG_DEBUG("success generate publickey");

  *sk = SecretKey(*pk, p, q);
}

}  // namespace heu::lib::algorithms::paillier_f
