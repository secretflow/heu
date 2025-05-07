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

#include "heu/library/algorithms/paillier_zahlen/evaluator.h"

#include "heu/library/algorithms/util/he_assert.h"

namespace heu::lib::algorithms::paillier_z {

#define VALIDATE(ct)                                          \
  HE_ASSERT(!(ct).c_.IsNegative() && (ct).c_ < pk_.n_square_, \
            "Evaluator: Invalid ciphertext")

void Evaluator::Randomize(Ciphertext *ct) const {
  VALIDATE(*ct);
  ct->c_ = pk_.m_space_->MulMod(ct->c_, encryptor_.GetRn());
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Ciphertext &b) const {
  VALIDATE(a);
  VALIDATE(b);

  Ciphertext out;
  out.c_ = pk_.m_space_->MulMod(a.c_, b.c_);
  return out;
}

void Evaluator::AddInplace(Ciphertext *a, const Ciphertext &b) const {
  VALIDATE(*a);
  VALIDATE(b);

  a->c_ = pk_.m_space_->MulMod(a->c_, b.c_);
}

Ciphertext Evaluator::Add(const Ciphertext &a, const BigInt &p) const {
  VALIDATE(a);
  YACL_ENFORCE(p.CompareAbs(pk_.PlaintextBound()) <= 0,
               "plaintext out of range, message={}, max (abs)={}",
               p.ToHexString(), pk_.PlaintextBound());

  // Note: g^m = (1 + n)^m = (1 + n*m) mod n^2
  // It is also correct when m is negative
  BigInt gm = pk_.n_ * p + 1;  // no need mod
  pk_.m_space_->MapIntoMSpace(gm);

  Ciphertext out;
  out.c_ = pk_.m_space_->MulMod(a.c_, gm);
  return out;
}

void Evaluator::AddInplace(Ciphertext *a, const BigInt &p) const {
  *a = Add(*a, p);
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const Ciphertext &b) const {
  return Add(a, Negate(b));
}

void Evaluator::SubInplace(Ciphertext *a, const Ciphertext &b) const {
  AddInplace(a, Negate(b));
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const BigInt &p) const {
  return Add(a, -p);
}

void Evaluator::SubInplace(Ciphertext *a, const BigInt &p) const {
  AddInplace(a, -p);
}

Ciphertext Evaluator::Sub(const BigInt &p, const Ciphertext &a) const {
  return Add(Negate(a), p);
}

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  VALIDATE(a);

  BigInt tmp(a.c_);
  pk_.m_space_->MapBackToZSpace(tmp);
  Ciphertext out;
  out.c_ = tmp.InvMod(pk_.n_square_);
  pk_.m_space_->MapIntoMSpace(out.c_);
  return out;
}

void Evaluator::NegateInplace(Ciphertext *a) const { *a = Negate(*a); }

Ciphertext Evaluator::Mul(const Ciphertext &a, const BigInt &p) const {
  // No need to check size of p because ciphertext overflow is allowed
  VALIDATE(a);

  // Handle some values specially to speed up computation
  auto p_bits = p.BitCount();
  if (p_bits == 0) {
    return Ciphertext(pk_.m_space_->Identity());
  } else if (p_bits == 1) {
    if (p.IsNegative()) {
      // p = -1
      return Negate(a);
    } else {
      // p == 1
      return a;
    }
  }

  Ciphertext out;
  BigInt c(a.c_);
  pk_.m_space_->MapBackToZSpace(c);
  out.c_ = c.PowMod(p, pk_.n_square_);
  pk_.m_space_->MapIntoMSpace(out.c_);
  return out;
}

void Evaluator::MulInplace(Ciphertext *a, const BigInt &p) const {
  *a = Mul(*a, p);
}

}  // namespace heu::lib::algorithms::paillier_z
