// Copyright 2024 CyberChangAn Group, Xidian University.
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

#include "heu/algorithms/incubator/ishe/evaluator.h"

#include <cstdint>

#include "heu/spi/he/encryptor.h"

namespace heu::algos::ishe {

Plaintext Evaluator::Negate(const Plaintext &a) const { return -a; }

void Evaluator::NegateInplace(Plaintext *a) const { a->NegateInplace(); }

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  // [[-1]] * a
  MPInt r;
  MPInt::RandomLtN(MPInt(pp_->NEGS.size()), &r);
  Ciphertext neg = Ciphertext(pp_->NEGS[r.Get<int64_t>()], {0_mp});
  MulInplace(&neg, a);
  return neg;
}

void Evaluator::NegateInplace(Ciphertext *a) const { *a = Negate(*a); }

Plaintext Evaluator::Add(const Plaintext &a, const Plaintext &b) const {
  return a + b;
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Plaintext &b) const {
  MPInt r;
  Ciphertext one;
  if (a.d_ == MPInt(1)) {
    MPInt::RandomLtN(MPInt(pp_->ONES.size()), &r);
    one = Ciphertext(pp_->ONES[r.Get<int64_t>()], {1_mp});
  } else {
    r = a.d_ - MPInt(1);
    one = Ciphertext(pp_->ADDONES[r.Get<int64_t>()], a.d_);
  }
  const auto m = Mul(one, b);
  return Ciphertext(a.n_ + m.n_, a.d_);
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Ciphertext &b) const {
  Ciphertext m1, m2;
  // make sure d_m1 is bigger than d_m2
  if (a.d_ == b.d_) {  // d_1 = d_2
    m1 = Ciphertext(a.n_ + b.n_, a.d_);
    return m1;
  }
  if (a.d_ > b.d_) {  // d_1 > d_2,
    m1 = a;
    m2 = b;
  } else {  // d_2 > d_1
    m2 = a;
    m1 = b;
  }
  const MPInt d = m1.d_ - m2.d_;
  const auto one = Ciphertext(pp_->ADDONES[d.Get<int64_t>() - 1], d);
  m2 = this->Mul(m2, one);
  return Add(m1, m2.n_);
}

void Evaluator::AddInplace(Ciphertext *a, const Plaintext &b) const {
  *a = Add(*a, b);
}

void Evaluator::AddInplace(Ciphertext *a, const Ciphertext &b) const {
  *a = Add(*a, b);
}

Ciphertext Evaluator::Mul(const Ciphertext &a, const Ciphertext &b) const {
  Ciphertext res;
  MPInt::MulMod(a.n_, b.n_, pp_->getN(), &res.n_);
  res.d_ = a.d_ + b.d_;
  return res;
}

Plaintext Evaluator::Mul(const Plaintext &a, const Plaintext &b) const {
  Plaintext res = a * b;
  return res;
}

Ciphertext Evaluator::Mul(const Ciphertext &a, const Plaintext &b) const {
  Ciphertext res;
  if (b >= Plaintext(0)) {
    MPInt::MulMod(a.n_, b, pp_->getN(), &res.n_);
  } else {
    MPInt::MulMod(Negate(a).n_, -b, pp_->getN(), &res.n_);
  }
  res.d_ = a.d_;
  return res;
}

void Evaluator::MulInplace(Ciphertext *a, const Plaintext &b) const {
  *a = Mul(*a, b);
}

void Evaluator::MulInplace(Ciphertext *a, const Ciphertext &b) const {
  *a = Mul(*a, b);
}

Plaintext Evaluator::Square(const Plaintext &a) const { return Mul(a, a); }

void Evaluator::SquareInplace(Plaintext *a) const { *a = Mul(*a, *a); }

Ciphertext Evaluator::Square(const Ciphertext &ciphertext) const {
  return Ciphertext(Square(ciphertext.n_), ciphertext.d_.Mul(2));
}

void Evaluator::SquareInplace(Ciphertext *ciphertext) const {
  *ciphertext = Square(*ciphertext);
}

Plaintext Evaluator::Pow(const Plaintext &a, int64_t exponent) const {
  return a.Pow(exponent);
}

void Evaluator::PowInplace(Plaintext *a, int64_t exponent) const {
  a->PowInplace(exponent);
}

Ciphertext Evaluator::Pow(const Ciphertext &ciphertext, int64_t int64) const {
  return Ciphertext(ciphertext.n_.Pow(int64), ciphertext.d_.Mul(int64));
}

void Evaluator::PowInplace(Ciphertext *ciphertext, int64_t int64) const {
  *ciphertext = Pow(*ciphertext, int64);
}

void Evaluator::Randomize(Ciphertext *ct) const {
  MPInt r;
  MPInt::RandomLtN(MPInt(pp_->ONES.size()), &r);
  const Ciphertext one = Ciphertext(pp_->ONES[r.Get<int64_t>()], MPInt(1));
  MulInplace(ct, one);
}

}  // namespace heu::algos::ishe
