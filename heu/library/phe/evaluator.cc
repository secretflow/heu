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

#include "heu/library/phe/evaluator.h"

namespace heu::lib::phe {

void Evaluator::Randomize(Ciphertext *ct) const {
  std::visit(
      HE_DISPATCH(HE_METHOD_T1_VOID, Evaluator, Randomize, Ciphertext, ct),
      evaluator_ptr_);
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Ciphertext &b) const {
  return std::visit(HE_DISPATCH(HE_METHOD_T1_T2_RET, Evaluator, Ciphertext, Add,
                                Ciphertext, a, Ciphertext, b),
                    evaluator_ptr_);
}

void Evaluator::AddInplace(Ciphertext *a, const Ciphertext &b) const {
  std::visit(HE_DISPATCH(HE_METHOD_T1_T2_VOID, Evaluator, AddInplace,
                         Ciphertext, a, Ciphertext, b),
             evaluator_ptr_);
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Plaintext &p) const {
  return std::visit(HE_DISPATCH(HE_METHOD_T1_MPINT_RET, Evaluator, Ciphertext,
                                Add, Ciphertext, a, p),
                    evaluator_ptr_);
}

void Evaluator::AddInplace(Ciphertext *a, const Plaintext &p) const {
  return std::visit(HE_DISPATCH(HE_METHOD_T1_MPINT_VOID, Evaluator, AddInplace,
                                Ciphertext, a, p),
                    evaluator_ptr_);
}

Ciphertext Evaluator::Add(const Plaintext &p, const Ciphertext &a) const {
  return Add(a, p);
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const Ciphertext &b) const {
  return std::visit(HE_DISPATCH(HE_METHOD_T1_T2_RET, Evaluator, Ciphertext, Sub,
                                Ciphertext, a, Ciphertext, b),
                    evaluator_ptr_);
}

void Evaluator::SubInplace(Ciphertext *a, const Ciphertext &b) const {
  return std::visit(HE_DISPATCH(HE_METHOD_T1_T2_VOID, Evaluator, SubInplace,
                                Ciphertext, a, Ciphertext, b),
                    evaluator_ptr_);
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const Plaintext &p) const {
  return std::visit(HE_DISPATCH(HE_METHOD_T1_MPINT_RET, Evaluator, Ciphertext,
                                Sub, Ciphertext, a, p),
                    evaluator_ptr_);
}

void Evaluator::SubInplace(Ciphertext *a, const Plaintext &p) const {
  return std::visit(HE_DISPATCH(HE_METHOD_T1_MPINT_VOID, Evaluator, SubInplace,
                                Ciphertext, a, p),
                    evaluator_ptr_);
}

Ciphertext Evaluator::Sub(const Plaintext &p, const Ciphertext &a) const {
  return std::visit(HE_DISPATCH(HE_METHOD_MPINT_T2_RET, Evaluator, Ciphertext,
                                Sub, p, Ciphertext, a),
                    evaluator_ptr_);
}

Ciphertext Evaluator::Mul(const Ciphertext &a, const Plaintext &p) const {
  return std::visit(HE_DISPATCH(HE_METHOD_T1_MPINT_RET, Evaluator, Ciphertext,
                                Mul, Ciphertext, a, p),
                    evaluator_ptr_);
}

Ciphertext Evaluator::Mul(const Plaintext &p, const Ciphertext &a) const {
  return Mul(a, p);
}

void Evaluator::MulInplace(Ciphertext *a, const Plaintext &p) const {
  std::visit(HE_DISPATCH(HE_METHOD_T1_MPINT_VOID, Evaluator, MulInplace,
                         Ciphertext, a, p),
             evaluator_ptr_);
}

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  return std::visit(HE_DISPATCH(HE_METHOD_T1_RET, Evaluator, Ciphertext, Negate,
                                Ciphertext, a),
                    evaluator_ptr_);
}

void Evaluator::NegateInplace(Ciphertext *a) const {
  std::visit(
      HE_DISPATCH(HE_METHOD_T1_VOID, Evaluator, NegateInplace, Ciphertext, a),
      evaluator_ptr_);
}

}  // namespace heu::lib::phe
