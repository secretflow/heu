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

#include "heu/algorithms/incubator/mock_phe/evaluator.h"

#include <cstdint>

namespace heu::algos::mock_phe {

Plaintext Evaluator::Negate(const Plaintext &a) const { return -a; }

void Evaluator::NegateInplace(Plaintext *a) const { a->NegateInplace(); }

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  return Ciphertext(-a.bn_);
}

void Evaluator::NegateInplace(Ciphertext *a) const { a->bn_.NegateInplace(); }

Plaintext Evaluator::Add(const Plaintext &a, const Plaintext &b) const {
  return a + b;
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Plaintext &b) const {
  YACL_ENFORCE(b.BitCount() <= pk_->KeySize(),
               "Plaintext {} is too large, cannot add", b);
  return Ciphertext(a.bn_ + b);
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Ciphertext &b) const {
  return Ciphertext(a.bn_ + b.bn_);
}

void Evaluator::AddInplace(Ciphertext *a, const Plaintext &b) const {
  YACL_ENFORCE(b.BitCount() <= pk_->KeySize(),
               "Plaintext {} is too large, cannot add", b);
  a->bn_ += b;
}

void Evaluator::AddInplace(Ciphertext *a, const Ciphertext &b) const {
  a->bn_ += b.bn_;
}

Plaintext Evaluator::Mul(const Plaintext &a, const Plaintext &b) const {
  return a * b;
}

Ciphertext Evaluator::Mul(const Ciphertext &a, const Plaintext &b) const {
  return Ciphertext(a.bn_ * b);
}

void Evaluator::MulInplace(Ciphertext *a, const Plaintext &b) const {
  a->bn_ *= b;
}

Plaintext Evaluator::Square(const Plaintext &a) const { return a * a; }

void Evaluator::SquareInplace(Plaintext *a) const { *a *= *a; }

Plaintext Evaluator::Pow(const Plaintext &a, int64_t exponent) const {
  return a.Pow(exponent);
}

void Evaluator::PowInplace(Plaintext *a, int64_t exponent) const {
  a->PowInplace(exponent);
}

void Evaluator::Randomize(Ciphertext *) const {}

}  // namespace heu::algos::mock_phe
