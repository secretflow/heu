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

#include "heu/library/algorithms/paillier_gpu/key_generator.h"

#include "yacl/base/exception.h"

#include "heu/library/algorithms/paillier_gpu/plaintext.h"

namespace heu::lib::algorithms::paillier_g {

namespace {
constexpr size_t kPQDifferenceBitLenSub = 2;  // >=1022-bit P-Q
}

void KeyGenerator::Generate(size_t key_size, SecretKey *sk, PublicKey *pk) {
  YACL_ENFORCE(key_size == 2048,
               "GPU Paillier only supports 2048 key_size now");

  Plaintext p, q, n, c;
  // To avoid square-root attacks, make sure the bit length of p-q is very
  // large.
  do {
    size_t half = key_size / 2;
    MPInt::RandPrimeOver(half, &p, PrimeType::BBS);
    do {
      MPInt::RandPrimeOver(half, &q, PrimeType::BBS);
      MPInt::Gcd(p - MPInt::_1_, q - MPInt::_1_, &c);
    } while (c != Plaintext(2) ||
             (p - q).BitCount() < key_size / 2 - kPQDifferenceBitLenSub);
    n = (Plaintext)(p * q);
  } while (n.BitCount() < key_size);

  MPInt x, h;
  do {
    MPInt::RandomLtN(n, &x);
    MPInt::Gcd(x, n, &c);
  } while (c != Plaintext(1));
  h = x * x * -MPInt::_1_ % n;

  // fill secret key
  sk->p_ = (Plaintext)p;
  sk->q_ = (Plaintext)q;
  sk->lambda_ = (Plaintext)(p.DecrOne() * q.DecrOne() / MPInt::_2_);
  MPInt::InvertMod(sk->lambda_, n, &sk->mu_);
  sk->Init();
  // fill public key
  pk->h_s_ = (Plaintext)(sk->PowModNSquareCrt(h, n));
  pk->n_ = std::move(n);
  pk->Init();
}

void KeyGenerator::Generate(SecretKey *sk, PublicKey *pk) {
  Generate(2048, sk, pk);
}

}  // namespace heu::lib::algorithms::paillier_g
