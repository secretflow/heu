// Copyright 2023 Clustar Technology Co., Ltd.
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

#include "key_generator.h"

#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

// key_size: unit in bit, 1024 bits is recommended in FPGA case
void KeyGenerator::Generate(int key_size, SecretKey* sk, PublicKey* pk) {
  MPInt p;
  MPInt q;
  MPInt n;

  int n_len = 0;
  while (n_len != key_size) {
    MPInt::RandPrimeOver(key_size / 2, &p);
    q = p;
    while (q == p) {
      MPInt::RandPrimeOver(key_size / 2, &q);
    }
    MPInt::Mul(p, q, &n);  // n = p * q;
    n_len = n.BitCount();
  }

  *pk = PublicKey(std::move(n));
  *sk = SecretKey(*pk, p, q);
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
