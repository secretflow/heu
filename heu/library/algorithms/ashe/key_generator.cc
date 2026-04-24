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

#include "heu/library/algorithms/ashe/key_generator.h"

#include <utility>

namespace heu::lib::algorithms::ashe {
void KeyGenerator::Generate(int key_size, SecretKey *sk, PublicParameters *pk) {
  int64_t k_r1, k_p, k_q, k_r2, k_m;
  ;
  if (key_size == 2048) {
    k_r1 = 4384;
    k_p = 1536;
    k_q = 1008;
    k_r2 = 512;
    k_m = 64;
  } else {
    k_r1 = 8832;
    k_p = 1536;
    k_q = 992;
    k_r2 = 512;
    k_m = 64;
  }
  std::vector<BigInt> zeros;
  BigInt p = BigInt::RandPrimeOver(k_p);
  const BigInt q = BigInt::RandPrimeOver(k_q);
  *sk = SecretKey(p, q);

  InitZeros(k_r1, k_p, k_q, k_r2, k_m, *sk, &zeros);
  *pk = PublicParameters(k_r1, k_p, k_q, k_r2, k_m, zeros);
}

void KeyGenerator::Generate(SecretKey *sk, PublicParameters *pk) {
  Generate(2048, sk, pk);
}

void KeyGenerator::InitZeros(int64_t k_r1, int64_t k_p, int64_t k_q,
                             int64_t k_r2, int64_t k_m, SecretKey sk_,
                             std::vector<BigInt> *zeros) {
  auto tmp = PublicParameters(k_r1, k_p, k_q, k_r2, k_m);
  auto et = Encryptor(tmp, std::move(sk_));
  for (int i = 1; i <= 20; ++i) {
    zeros->emplace_back(et.Encrypt(BigInt(0)).n_);
  }
}
}  // namespace heu::lib::algorithms::ashe
