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

#include "heu/library/algorithms/paillier_ic/decryptor.h"

#include "heu/library/algorithms/util/he_assert.h"

namespace heu::lib::algorithms::paillier_ic {

#define VALIDATE(ct)                                          \
  HE_ASSERT(!(ct).c_.IsNegative() && (ct).c_ < pk_.n_square_, \
            "Decryptor: Invalid ciphertext")

void Decryptor::Decrypt(const Ciphertext &ct, MPInt *out) const {
  VALIDATE(ct);

  MPInt mp;
  MPInt::PowMod(ct.c_, sk_.phi_p_, sk_.p_square_, &mp);
  mp = mp.DecrOne() / sk_.p_;
  MPInt::MulMod(mp, sk_.hp_, sk_.p_, &mp);

  MPInt mq;
  MPInt::PowMod(ct.c_, sk_.phi_q_, sk_.q_square_, &mq);
  mq = mq.DecrOne() / sk_.q_;
  MPInt::MulMod(mq, sk_.hq_, sk_.q_, &mq);

  // Apply the CRT
  MPInt::MulMod(mq - mp, sk_.p_inv_mod_q_, sk_.q_, out);
  MPInt::Mul(*out, sk_.p_, out);
  MPInt::Add(*out, mp, out);

  // Handle negative numbers
  if (*out > pk_.n_half_) {
    *out -= pk_.n_;
  }
}

MPInt Decryptor::Decrypt(const Ciphertext &ct) const {
  MPInt mp;
  Decrypt(ct, &mp);
  return mp;
}

}  // namespace heu::lib::algorithms::paillier_ic
