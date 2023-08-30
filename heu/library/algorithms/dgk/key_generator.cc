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

#include "yacl/base/exception.h"

#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::dgk {

void KeyGenerator::Generate(size_t key_size, SecretKey* sk, PublicKey* pk) {
  YACL_ENFORCE(key_size % 2 == 0, "Key size must be even");
  YACL_ENFORCE(key_size >= 1024 && key_size <= 3072,
               "Key size must be in [1024, 3072] and 2048 bits is recommended");

  MPInt u, vp, vq;
  // MPINT_ENFORCE_OK(
  //     mp_prime_rand(reinterpret_cast<mp_int*>(&u), 1, l, MP_PRIME_BBS));
  u = MPInt{65423};  // use the largest l(16)-bit prime instead
  MPInt::RandPrimeOver(t, &vp);
  MPInt::RandPrimeOver(t, &vq);
  // Question: can we consider the following generations of p, q secure?
  // TODO: check NIST.FIPS.186-5 Appendix A.1.1
  MPInt wp, wq, p, q, gcd;
  do {
    MPInt::RandomMonicExactBits(key_size / 2 - t - l, &wp);
    MPInt::Gcd(wp, vq, &gcd);
    wp *= MPInt::_2_;
    p = u * vp * wp + MPInt::_1_;
  } while (!p.IsPrime() || gcd != MPInt::_1_);
  do {
    MPInt::RandomMonicExactBits(key_size / 2 - t, &wq);
    MPInt::Gcd(wq, vp, &gcd);
    wq *= MPInt::_2_;
    q = vq * wq + MPInt::_1_;
  } while (!q.IsPrime() || gcd != MPInt::_1_);
  MPInt n{p * q}, pp_{p * p.InvertMod(q)};
  MPInt gp, gq, gn;  // generators of cyclic groups
  do {
    MPInt::RandomLtN(p, &gp);
  } while (gp.PowMod(u * vp, p) == MPInt::_1_ ||
           gp.PowMod(vp * wp, p) == MPInt::_1_ ||
           gp.PowMod(wp * u, p) == MPInt::_1_);
  do {
    MPInt::RandomLtN(q, &gq);
  } while (gq.PowMod(vq, q) == MPInt::_1_ || gq.PowMod(wq, q) == MPInt::_1_);
  gn = (gp + (gq - gp) * pp_) % n;
  MPInt g, h;
  g = gn.PowMod(wp * wq, n);
  h = g.PowMod(u, n);

  sk->Init(p, q, vp, vq, u, g);
  pk->Init(n, g, h, u);
}

void KeyGenerator::Generate(SecretKey* sk, PublicKey* pk) {
  Generate(2048, sk, pk);
}

}  // namespace heu::lib::algorithms::dgk
