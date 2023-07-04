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

#include "heu/library/algorithms/elgamal/scalar_evaluator.h"

namespace heu::lib::algorithms::elgamal {

Evaluator::Evaluator(const PublicKey &pk) : pk_(pk) {
  ec_ = pk_.GetCurve();
  Ciphertext::EnableEcGroup(ec_);
}

void Evaluator::Randomize(Ciphertext *ct) const {
  MPInt r;
  MPInt::RandomLtN(ec_->GetField(), &r);
  AddInplace(ct, Ciphertext(ec_, ec_->MulBase(r), ec_->Mul(pk_.GetH(), r)));
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Ciphertext &b) const {
  return Ciphertext(ec_, ec_->Add(a.c1, b.c1), ec_->Add(a.c2, b.c2));
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Plaintext &b) const {
  return Ciphertext(ec_, a.c1, ec_->Add(a.c2, ec_->MulBase(b)));
}

Ciphertext Evaluator::Add(const Plaintext &a, const Ciphertext &b) const {
  return Add(b, a);
}

Plaintext Evaluator::Add(const Plaintext &a, const Plaintext &b) const {
  return a + b;
}

void Evaluator::AddInplace(Ciphertext *a, const Ciphertext &b) const {
  ec_->AddInplace(&a->c1, b.c1);
  ec_->AddInplace(&a->c2, b.c2);
}

void Evaluator::AddInplace(Ciphertext *a, const Plaintext &b) const {
  ec_->AddInplace(&a->c2, ec_->MulBase(b));
}

void Evaluator::AddInplace(Plaintext *a, const Plaintext &b) const { *a += b; }

Ciphertext Evaluator::Sub(const Ciphertext &a, const Ciphertext &b) const {
  return Ciphertext(ec_, ec_->Sub(a.c1, b.c1), ec_->Sub(a.c2, b.c2));
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const Plaintext &b) const {
  return Ciphertext(ec_, a.c1, ec_->Sub(a.c2, ec_->MulBase(b)));
}

Ciphertext Evaluator::Sub(const Plaintext &a, const Ciphertext &b) const {
  return Ciphertext(ec_, ec_->Negate(b.c1), ec_->Sub(ec_->MulBase(a), b.c2));
}

Plaintext Evaluator::Sub(const Plaintext &a, const Plaintext &b) const {
  return a - b;
}

void Evaluator::SubInplace(Ciphertext *a, const Ciphertext &b) const {
  ec_->SubInplace(&a->c1, b.c1);
  ec_->SubInplace(&a->c2, b.c2);
}

void Evaluator::SubInplace(Ciphertext *a, const Plaintext &p) const {
  ec_->SubInplace(&a->c2, ec_->MulBase(p));
}

void Evaluator::SubInplace(Plaintext *a, const Plaintext &b) const { *a -= b; }

Ciphertext Evaluator::Mul(const Ciphertext &a, const Plaintext &b) const {
  return Ciphertext(ec_, ec_->Mul(a.c1, b), ec_->Mul(a.c2, b));
}

Ciphertext Evaluator::Mul(const Plaintext &a, const Ciphertext &b) const {
  return Mul(b, a);
}

Plaintext Evaluator::Mul(const Plaintext &a, const Plaintext &b) const {
  return a * b;
}

void Evaluator::MulInplace(Ciphertext *a, const Plaintext &b) const {
  ec_->MulInplace(&a->c1, b);
  ec_->MulInplace(&a->c2, b);
}

void Evaluator::MulInplace(Plaintext *a, const Plaintext &b) const { *a *= b; }

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  return Ciphertext(ec_, ec_->Negate(a.c1), ec_->Negate(a.c2));
}

void Evaluator::NegateInplace(Ciphertext *a) const {
  ec_->NegateInplace(&a->c1);
  ec_->NegateInplace(&a->c2);
}

}  // namespace heu::lib::algorithms::elgamal
