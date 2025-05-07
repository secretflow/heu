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

void Decryptor::Decrypt(const Ciphertext &ct, BigInt *out) const {
  VALIDATE(ct);

  BigInt mp = ct.c_.PowMod(sk_.phi_p_, sk_.p_square_);
  mp = ((mp - 1) / sk_.p_).MulMod(sk_.hp_, sk_.p_);

  BigInt mq = ct.c_.PowMod(sk_.phi_q_, sk_.q_square_);
  mq = ((mq - 1) / sk_.q_).MulMod(sk_.hq_, sk_.q_);

  // Apply the CRT
  *out = (mq - mp).MulMod(sk_.p_inv_mod_q_, sk_.q_);
  *out *= sk_.p_;
  *out += mp;

  // Handle negative numbers
  if (*out > pk_.n_half_) {
    *out -= pk_.n_;
  }
}

BigInt Decryptor::Decrypt(const Ciphertext &ct) const {
  BigInt mp;
  Decrypt(ct, &mp);
  return mp;
}

}  // namespace heu::lib::algorithms::paillier_ic
