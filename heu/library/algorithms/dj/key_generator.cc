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

#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::dj {

void KeyGenerator::Generate(size_t key_size, SecretKey* sk, PublicKey* pk) {
  YACL_ENFORCE(key_size % 2 == 0, "Key size must be even");

  MPInt p, q, gcd;
  MPInt::RandPrimeOver(key_size / 2, &p, PrimeType::BBS);
  do {
    MPInt::RandPrimeOver(key_size / 2, &q, PrimeType::BBS);
    MPInt::Gcd(p - MPInt::_1_, q - MPInt::_1_, &gcd);
  } while (gcd != MPInt::_2_);
  sk->Init(p, q, s_);
  pk->Init(p * q, s_);
}

void KeyGenerator::Generate(SecretKey* sk, PublicKey* pk) {
  Generate(2048, sk, pk);
}

}  // namespace heu::lib::algorithms::dj
