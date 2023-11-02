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

#include "heu/library/algorithms/paillier_dl/key_generator.h"

#include "yacl/base/exception.h"

#include "heu/library/algorithms/util/mp_int.h"
namespace heu::lib::algorithms::paillier_dl {

namespace {

constexpr size_t kPQDifferenceBitLenSub = 2;  // >=1022-bit P-Q
}

void KeyGenerator::Generate(size_t key_size, SecretKey* sk, PublicKey* pk) {
  YACL_ENFORCE(key_size % 2 == 0, "Key size must be even");

  MPInt p, q, n, c;

  // To avoid square-root attacks, make sure the bit length of p-q is very
  // large.
  do {
    size_t half = key_size / 2;
    MPInt::RandPrimeOver(half, &p, PrimeType::BBS);
    do {
      MPInt::RandPrimeOver(half, &q, PrimeType::BBS);
      MPInt::Gcd(p - MPInt::_1_, q - MPInt::_1_, &c);
    } while (c != MPInt(2) ||
             (p - q).BitCount() < key_size / 2 - kPQDifferenceBitLenSub);
    n = p * q;
  } while (n.BitCount() < key_size);

  MPInt g;
  pk->Init(n, g);
  sk->Init(g, p, q);
}

}  // namespace heu::lib::algorithms::paillier_dl
