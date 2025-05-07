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

#include "heu/library/algorithms/paillier_ic/evaluator.h"

#include "heu/library/algorithms/util/he_assert.h"

namespace heu::lib::algorithms::paillier_ic {

#define VALIDATE(ct)                                          \
  HE_ASSERT(!(ct).c_.IsNegative() && (ct).c_ < pk_.n_square_, \
            "Evaluator: Invalid ciphertext")

void Evaluator::Randomize(Ciphertext *ct) const {
  VALIDATE(*ct);
  ct->c_ = ct->c_.MulMod(encryptor_.GetRn(), pk_.n_square_);
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Ciphertext &b) const {
  VALIDATE(a);
  VALIDATE(b);
  return Ciphertext{a.c_.MulMod(b.c_, pk_.n_square_)};
}

void Evaluator::AddInplace(Ciphertext *a, const Ciphertext &b) const {
  VALIDATE(*a);
  VALIDATE(b);

  a->c_ = a->c_.MulMod(b.c_, pk_.n_square_);
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Plaintext &p) const {
  VALIDATE(a);
  YACL_ENFORCE(p.CompareAbs(pk_.PlaintextBound()) <= 0,
               "plaintext out of range, message={}, max (abs)={}",
               p.ToHexString(), pk_.PlaintextBound());
  BigInt gm = pk_.n_ * p + 1;  // no need mod
  return Ciphertext{a.c_.MulMod(gm, pk_.n_square_)};
}

void Evaluator::AddInplace(Ciphertext *a, const Plaintext &p) const {
  *a = Add(*a, p);
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const Ciphertext &b) const {
  return Add(a, Negate(b));
}

void Evaluator::SubInplace(Ciphertext *a, const Ciphertext &b) const {
  AddInplace(a, Negate(b));
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const Plaintext &p) const {
  return Add(a, -p);
}

void Evaluator::SubInplace(Ciphertext *a, const Plaintext &p) const {
  AddInplace(a, -p);
}

Ciphertext Evaluator::Sub(const Plaintext &p, const Ciphertext &a) const {
  return Add(Negate(a), p);
}

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  VALIDATE(a);
  return Ciphertext(a.c_.InvMod(pk_.n_square_));
}

void Evaluator::NegateInplace(Ciphertext *a) const { *a = Negate(*a); }

Ciphertext Evaluator::Mul(const Ciphertext &a, const Plaintext &p) const {
  VALIDATE(a);
  return Ciphertext(a.c_.PowMod(p, pk_.n_square_));
}

void Evaluator::MulInplace(Ciphertext *a, const Plaintext &p) const {
  *a = Mul(*a, p);
}

}  // namespace heu::lib::algorithms::paillier_ic
