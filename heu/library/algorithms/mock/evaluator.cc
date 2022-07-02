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

#include "heu/library/algorithms/mock/evaluator.h"

namespace heu::lib::algorithms::mock {

void Evaluator::Randomize(Ciphertext* ct) const { (void)ct; }

Ciphertext Evaluator::Add(const Ciphertext& a, const Ciphertext& b) const {
  Ciphertext out;
  out.c_ = a.c_ + b.c_;
  return out;
}

void Evaluator::AddInplace(Ciphertext* a, const Ciphertext& b) const {
  *a = Add(*a, b);
}

Ciphertext Evaluator::Add(const Ciphertext& a, const MPInt& p) const {
  YASL_ENFORCE(p.CompareAbs(pk_.PlaintextBound()) < 0,
               "plaintext number out of range, message={}, max (abs)={}",
               p.ToHexString(), pk_.PlaintextBound());

  Ciphertext out;
  out.c_ = a.c_ + p;
  return out;
}

void Evaluator::AddInplace(Ciphertext* a, const MPInt& p) const {
  *a = Add(*a, p);
}

Ciphertext Evaluator::Sub(const Ciphertext& a, const Ciphertext& b) const {
  Ciphertext out;
  out.c_ = a.c_ - b.c_;
  return out;
}

void Evaluator::SubInplace(Ciphertext* a, const Ciphertext& b) const {
  *a = Sub(*a, b);
}

Ciphertext Evaluator::Sub(const Ciphertext& a, const MPInt& p) const {
  YASL_ENFORCE(p.CompareAbs(pk_.PlaintextBound()) < 0,
               "plaintext number out of range, message={}, max (abs)={}",
               p.ToHexString(), pk_.PlaintextBound());

  Ciphertext out;
  out.c_ = a.c_ - p;
  return out;
}

void Evaluator::SubInplace(Ciphertext* a, const MPInt& p) const {
  *a = Sub(*a, p);
}

Ciphertext Evaluator::Sub(const MPInt& p, const Ciphertext& a) const {
  Ciphertext out;
  out.c_ = p - a.c_;
  return out;
}

Ciphertext Evaluator::Negate(const Ciphertext& a) const {
  Ciphertext out;
  a.c_.Negate(&out.c_);
  return out;
}

void Evaluator::NegateInplace(Ciphertext* a) const { *a = Negate(*a); }

Ciphertext Evaluator::Mul(const Ciphertext& a, const MPInt& p) const {
  // Keep same with Paillier/OU
  // No need to check size of p because ciphertext overflow is allowed

  Ciphertext out;
  out.c_ = a.c_ * p;
  return out;
}

void Evaluator::MulInplace(Ciphertext* a, const MPInt& p) const {
  *a = Mul(*a, p);
}

}  // namespace heu::lib::algorithms::mock
