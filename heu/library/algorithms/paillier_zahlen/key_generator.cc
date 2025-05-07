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

#include "heu/library/algorithms/paillier_zahlen/key_generator.h"

#include "yacl/base/exception.h"

namespace heu::lib::algorithms::paillier_z {

namespace {

constexpr size_t kPQDifferenceBitLenSub = 2;  // >=1022-bit P-Q
}

void KeyGenerator::Generate(size_t key_size, SecretKey *sk, PublicKey *pk) {
  YACL_ENFORCE(key_size % 2 == 0, "Key size must be even");

  BigInt p, q, n, c;
  // To avoid square-root attacks, make sure the bit length of p-q is very
  // large.
  do {
    size_t half = key_size / 2;
    p = BigInt::RandPrimeOver(half, PrimeType::BBS);
    do {
      q = BigInt::RandPrimeOver(half, PrimeType::BBS);
      c = (p - 1).Gcd(q - 1);
    } while (c != 2 ||
             (p - q).BitCount() < key_size / 2 - kPQDifferenceBitLenSub);
    n = p * q;
  } while (n.BitCount() < key_size);

  BigInt x, h;
  do {
    x = BigInt::RandomLtN(n);
    c = x.Gcd(n);
  } while (c != 1);
  h = -x.MulMod(x, n);

  // fill secret key
  sk->p_ = p;
  sk->q_ = q;
  sk->lambda_ = (p - 1) * (q - 1) / 2;
  sk->mu_ = sk->lambda_.InvMod(n);
  sk->Init();
  // fill public key
  pk->h_s_ = sk->PowModNSquareCrt(h, n);
  pk->n_ = std::move(n);
  pk->Init();
}

void KeyGenerator::Generate(SecretKey *sk, PublicKey *pk) {
  Generate(2048, sk, pk);
}

}  // namespace heu::lib::algorithms::paillier_z
