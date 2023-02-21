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

#include "heu/library/algorithms/ou/decryptor.h"

#include "heu/library/algorithms/util/he_assert.h"
#include "heu/library/algorithms/util/montgomery_math.h"

namespace heu::lib::algorithms::ou {

#define VALIDATE(ct)                                   \
  HE_ASSERT(!(ct).c_.IsNegative() && (ct).c_ < pk_.n_, \
            "Decryptor: Invalid ciphertext")

void Decryptor::Decrypt(const Ciphertext& ct, MPInt* out) const {
  VALIDATE(ct);

  MPInt c(ct.c_);
  pk_.m_space_->MapBackToZSpace(&c);
  MPInt::PowMod(c % sk_.p2_, sk_.t_, sk_.p2_, &c);
  c.DecrOne();
  MPInt::MulMod(c / sk_.p_, sk_.gp_inv_, sk_.p_, out);

  // handle negative numbers
  if (*out >= sk_.p_half_) {
    *out -= sk_.p_;
  }
}

MPInt Decryptor::Decrypt(const Ciphertext& ct) const {
  MPInt mp;
  Decrypt(ct, &mp);
  return mp;
}

}  // namespace heu::lib::algorithms::ou
