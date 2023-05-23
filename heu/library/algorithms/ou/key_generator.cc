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

#include "heu/library/algorithms/ou/key_generator.h"

namespace heu::lib::algorithms::ou {

// according to this paper
// << Accelerating Okamoto-Uchiyama’s Public-Key Cryptosystem >>
// and NIST's recommendation:
// https://www.keylength.com/en/4/
// 160 bits for key size 1024; 224 bits for key size 2048
constexpr static size_t kPrimeFactorSize1024 = 160;
constexpr static size_t kPrimeFactorSize2048 = 224;
constexpr static size_t kPrimeFactorSize3072 = 256;

void KeyGenerator::Generate(size_t key_size, SecretKey* sk, PublicKey* pk) {
  size_t secret_size = (key_size + 2) / 3;

  auto prime_factor_size = kPrimeFactorSize1024;
  if (key_size >= 3072) {
    prime_factor_size = kPrimeFactorSize3072;
  } else if (key_size >= 2048) {
    prime_factor_size = kPrimeFactorSize2048;
  }

  YACL_ENFORCE(prime_factor_size * 2 <= secret_size,
               "Key size must be larger than {} bits",
               prime_factor_size * 2 * 3 - 2);

  MPInt u, prime_factor;
  do {
    MPInt::RandPrimeOver(prime_factor_size, &prime_factor);
    // bits_of(a * b) <= bits_of(a) + bits_of(b)
    // So we add extra two bits to u:
    //    one bit for prime_factor * u; another one bit for p^2;
    // Also, make sure that u > prime_factor
    MPInt::RandomMonicExactBits(secret_size - prime_factor_size + 2, &u);
    sk->p_ = prime_factor * u + MPInt::_1_;  // p - 1 has a large prime factor
  } while (!sk->p_.IsPrime());
  // since bits_of(a * b) <= bits_of(a) + bits_of(b)
  // add another 1 bit for q
  MPInt::RandPrimeOver(secret_size + 1, &sk->q_);
  sk->p2_ = sk->p_ * sk->p_;
  sk->p_half_ = sk->p_ / MPInt::_2_;
  sk->t_ = prime_factor;
  sk->n_ = sk->p2_ * sk->q_;

  pk->n_ = sk->n_;

  MPInt g, g_, gp, check, gcd;
  do {
    do {
      MPInt::RandomLtN(pk->n_, &g);
      MPInt::Gcd(g, sk->p_, &gcd);
    } while (gcd != MPInt::_1_);
    MPInt::PowMod(g % sk->p2_, sk->p_ - MPInt::_1_, sk->p2_, &gp);
    MPInt::PowMod(gp, sk->p_, sk->p2_, &check);
  } while (check != MPInt::_1_);

  MPInt::InvertMod((gp - MPInt::_1_) / sk->p_, sk->p_, &sk->gp_inv_);

  // make sure 'g_' and 'p^2' are co-prime
  do {
    MPInt::RandomLtN(pk->n_, &g_);
  } while (g_.Mod(sk->p_).IsZero());
  MPInt::PowMod(g, u, pk->n_, &pk->capital_g_);
  MPInt::PowMod(g_, pk->n_ * u, pk->n_, &pk->capital_h_);

  // Note 1: About plaintext overflow attack:
  // https://staff.csie.ncu.edu.tw/yensm/techreports/1998/LCIS_TR-98-8B.ps.gz
  // proposes an overflow attack method, but due to the existence of plaintext
  // multiplication, No matter how small the 'max_plaintext_' limit is,
  // the plaintext space can overflow, so a small limit of 'max_plaintext_'
  // has little effect against this attack
  // Note 2:
  // A smaller max_plaintext_ can generate a denser cache table.
  // If you modify 'max_plaintext_', please modify the cache table density in
  // public_key.cc as well.
  // Note 3:
  // max_plaintext_ must be a power of 2, for ease of use
  pk->max_plaintext_ = MPInt::_1_ << (sk->p_half_.BitCount() - 1);
  pk->Init();
}

}  // namespace heu::lib::algorithms::ou
