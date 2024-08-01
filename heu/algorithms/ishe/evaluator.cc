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

#include "heu/algorithms/ishe/evaluator.h"

#include <cstdint>

#include "heu/spi/he/encryptor.h"

namespace heu::algos::ishe {

Plaintext Evaluator::Negate(const Plaintext &a) const { return -a; }

void Evaluator::NegateInplace(Plaintext *a) const { a->NegateInplace(); }

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  // [[-1]] * a
  Ciphertext neg;
  neg = et_->Encrypt(MPInt(-1));
  MulInplace(&neg, a);
  return neg;
}

void Evaluator::NegateInplace(Ciphertext *a) const { *a = Negate(*a); }

Plaintext Evaluator::Add(const Plaintext &a, const Plaintext &b) const {
  return a + b;
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Plaintext &b) const {
  Ciphertext m;
  if (b >= Plaintext(0)) {
    const auto onePre = Plaintext(1);
    const auto ONE = et_->Encrypt(onePre);
    m = Mul(ONE, b);
  } else {
    const auto onePre = Plaintext(-1);
    const auto ONE = et_->Encrypt(onePre);
    m = Mul(ONE, -b);
  }
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
  const auto ONE = et_->Encrypt(MPInt(1), m1.d_ - m2.d_);
  m2 = this->Mul(m2, ONE);
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
  MPInt::MulMod(a.n_, b.n_, pk_->getN(), &res.n_);
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
    MPInt::MulMod(a.n_, b, pk_->getN(), &res.n_);
    res.d_ = a.d_;
  } else {
    const auto ONE = et_->Encrypt(MPInt(-1), MPInt(1));
    MPInt::Mul(a.n_, -b, &res.n_);
    res.d_ = a.d_ + MPInt(1);
    MPInt::MulMod(res.n_, ONE.n_, pk_->getN(), &res.n_);
  }

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

Plaintext Evaluator::Pow(const Plaintext &a, int64_t exponent) const {
  return a.Pow(exponent);
}

void Evaluator::PowInplace(Plaintext *a, int64_t exponent) const {
  a->PowInplace(exponent);
}

void Evaluator::Randomize(Ciphertext *ct) const {
  const Ciphertext zero = et_->Encrypt(MPInt(0), ct->d_);
  ct->n_ += zero.n_;
}

}  // namespace heu::algos::ishe
