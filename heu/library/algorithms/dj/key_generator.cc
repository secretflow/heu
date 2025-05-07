// Copyright 2023 zhangwfjh
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

#include "heu/library/algorithms/dj/key_generator.h"

#include "yacl/base/exception.h"

namespace heu::lib::algorithms::dj {

void KeyGenerator::Generate(size_t key_size, SecretKey *sk, PublicKey *pk) {
  YACL_ENFORCE(key_size % 2 == 0, "Key size must be even");

  BigInt q, gcd;
  BigInt p = BigInt::RandPrimeOver(key_size / 2, PrimeType::BBS);
  do {
    q = BigInt::RandPrimeOver(key_size / 2, PrimeType::BBS);
    gcd = (p - 1).Gcd(q - 1);
  } while (gcd != 2);
  sk->Init(p, q, s_);
  pk->Init(p * q, s_, BigInt{0});
}

void KeyGenerator::Generate(SecretKey *sk, PublicKey *pk) {
  Generate(2048, sk, pk);
}

}  // namespace heu::lib::algorithms::dj
