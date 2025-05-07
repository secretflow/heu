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

#include "heu/library/algorithms/dgk/key_generator.h"

namespace heu::lib::algorithms::dgk {

void KeyGenerator::Generate(size_t key_size, SecretKey *sk, PublicKey *pk) {
  YACL_ENFORCE(key_size % 2 == 0, "Key size must be even");
  YACL_ENFORCE(key_size >= 1024 && key_size <= 3072,
               "Key size must be in [1024, 3072] and 2048 bits is recommended");

  // MPINT_ENFORCE_OK(
  //     mp_prime_rand(reinterpret_cast<mp_int*>(&u), 1, l, MP_PRIME_BBS));
  BigInt u(65423);  // use the largest l(16)-bit prime instead
  BigInt vp = BigInt::RandPrimeOver(t);
  BigInt vq = BigInt::RandPrimeOver(t);
  // Question: can we consider the following generations of p, q secure?
  // TODO: check NIST.FIPS.186-5 Appendix A.1.1
  BigInt wp, wq, p, q, gcd;
  do {
    wp = BigInt::RandomMonicExactBits(key_size / 2 - t - l);
    gcd = wp.Gcd(vq);
    wp *= 2;
    p = u * vp * wp + 1;
  } while (!p.IsPrime() || gcd != 1);
  do {
    wq = BigInt::RandomMonicExactBits(key_size / 2 - t);
    gcd = wq.Gcd(vp);
    wq *= 2;
    q = vq * wq + 1;
  } while (!q.IsPrime() || gcd != 1);
  BigInt n{p * q}, pp_{p * p.InvMod(q)};
  BigInt gp, gq, gn;  // generators of cyclic groups
  do {
    gp = BigInt::RandomLtN(p);
  } while (gp.PowMod(u * vp, p) == 1 || gp.PowMod(vp * wp, p) == 1 ||
           gp.PowMod(wp * u, p) == 1);
  do {
    gq = BigInt::RandomLtN(q);
  } while (gq.PowMod(vq, q) == 1 || gq.PowMod(wq, q) == 1);
  gn = (gp + (gq - gp) * pp_) % n;
  BigInt g, h;
  g = gn.PowMod(wp * wq, n);
  h = g.PowMod(u, n);

  sk->Init(p, q, vp, vq, u, g);
  pk->Init(n, g, h, u);
}

void KeyGenerator::Generate(SecretKey *sk, PublicKey *pk) {
  Generate(2048, sk, pk);
}

}  // namespace heu::lib::algorithms::dgk
