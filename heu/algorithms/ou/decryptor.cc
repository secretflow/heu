// Copyright 2024 Ant Group Co., Ltd.
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

#include "heu/algorithms/ou/decryptor.h"

#include "heu/algorithms/common/he_assert.h"

namespace heu::algos::ou {

#define VALIDATE(ct)                                    \
  HE_ASSERT(!(ct).c_.IsNegative() && (ct).c_ < pk_->n_, \
            "Decryptor: Invalid ciphertext")

Decryptor::Decryptor(const std::shared_ptr<PublicKey> &pk,
                     const std::shared_ptr<SecretKey> &sk)
    : pk_(pk), sk_(sk) {
  YACL_ENFORCE(sk_->p2_ * sk_->q_ == pk_->n_,
               "pk and sk are not paired, {}^2 * {} != {}", sk_->p_, sk_->q_,
               pk_->n_);
}

void Decryptor::Decrypt(const Ciphertext &ct, Plaintext *out) const {
  VALIDATE(ct);

  BigInt c(ct.c_);
  pk_->m_space_->MapBackToZSpace(c);
  c = (c % sk_->p2_).PowMod(sk_->t_, sk_->p2_);
  --c;
  *out = (c / sk_->p_).MulMod(sk_->gp_inv_, sk_->p_);

  // handle negative numbers
  if (*out > sk_->p_half_) {
    *out -= sk_->p_;
  }
}

Plaintext Decryptor::Decrypt(const Ciphertext &ct) const {
  BigInt mp;
  Decrypt(ct, &mp);
  return mp;
}

}  // namespace heu::algos::ou
