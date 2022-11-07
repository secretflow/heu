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

#include "heu/library/phe/base/predefined_functions.h"

namespace heu::lib::phe {

DEFINE_INVOKE_METHOD_VOID_1(Randomize);

void Evaluator::Randomize(Ciphertext *ct) const {
  std::visit(HE_DISPATCH(DO_INVOKE_METHOD_VOID_1, Evaluator, Randomize,
                         Ciphertext, ct),
             evaluator_ptr_);
}

DEFINE_INVOKE_METHOD_RET_2(Ciphertext, Add);
DEFINE_INVOKE_METHOD_VOID_2(AddInplace);

Ciphertext Evaluator::Add(const Ciphertext &a, const Ciphertext &b) const {
  return std::visit(HE_DISPATCH(DO_INVOKE_METHOD_RET_2, Evaluator, Add,
                                Ciphertext, a, Ciphertext, b),
                    evaluator_ptr_);
}

void Evaluator::AddInplace(Ciphertext *a, const Ciphertext &b) const {
  std::visit(HE_DISPATCH(DO_INVOKE_METHOD_VOID_2, Evaluator, AddInplace,
                         Ciphertext, a, Ciphertext, b),
             evaluator_ptr_);
}

Ciphertext Evaluator::Add(const Ciphertext &a, const Plaintext &p) const {
  return std::visit(HE_DISPATCH(DO_INVOKE_METHOD_RET_2, Evaluator, Add,
                                Ciphertext, a, Plaintext, p),
                    evaluator_ptr_);
}

void Evaluator::AddInplace(Ciphertext *a, const Plaintext &p) const {
  return std::visit(HE_DISPATCH(DO_INVOKE_METHOD_VOID_2, Evaluator, AddInplace,
                                Ciphertext, a, Plaintext, p),
                    evaluator_ptr_);
}

Ciphertext Evaluator::Add(const Plaintext &p, const Ciphertext &a) const {
  return Add(a, p);
}

DEFINE_INVOKE_METHOD_RET_2(Ciphertext, Sub);
DEFINE_INVOKE_METHOD_VOID_2(SubInplace);

Ciphertext Evaluator::Sub(const Ciphertext &a, const Ciphertext &b) const {
  return std::visit(HE_DISPATCH(DO_INVOKE_METHOD_RET_2, Evaluator, Sub,
                                Ciphertext, a, Ciphertext, b),
                    evaluator_ptr_);
}

void Evaluator::SubInplace(Ciphertext *a, const Ciphertext &b) const {
  return std::visit(HE_DISPATCH(DO_INVOKE_METHOD_VOID_2, Evaluator, SubInplace,
                                Ciphertext, a, Ciphertext, b),
                    evaluator_ptr_);
}

Ciphertext Evaluator::Sub(const Ciphertext &a, const Plaintext &p) const {
  return std::visit(HE_DISPATCH(DO_INVOKE_METHOD_RET_2, Evaluator, Sub,
                                Ciphertext, a, Plaintext, p),
                    evaluator_ptr_);
}

void Evaluator::SubInplace(Ciphertext *a, const Plaintext &p) const {
  return std::visit(HE_DISPATCH(DO_INVOKE_METHOD_VOID_2, Evaluator, SubInplace,
                                Ciphertext, a, Plaintext, p),
                    evaluator_ptr_);
}

Ciphertext Evaluator::Sub(const Plaintext &p, const Ciphertext &a) const {
  return std::visit(HE_DISPATCH(DO_INVOKE_METHOD_RET_2, Evaluator, Sub,
                                Plaintext, p, Ciphertext, a),
                    evaluator_ptr_);
}

DEFINE_INVOKE_METHOD_RET_2(Ciphertext, Mul);
DEFINE_INVOKE_METHOD_VOID_2(MulInplace);

Ciphertext Evaluator::Mul(const Ciphertext &a, const Plaintext &p) const {
  return std::visit(HE_DISPATCH(DO_INVOKE_METHOD_RET_2, Evaluator, Mul,
                                Ciphertext, a, Plaintext, p),
                    evaluator_ptr_);
}

Ciphertext Evaluator::Mul(const Plaintext &p, const Ciphertext &a) const {
  return Mul(a, p);
}

void Evaluator::MulInplace(Ciphertext *a, const Plaintext &p) const {
  std::visit(HE_DISPATCH(DO_INVOKE_METHOD_VOID_2, Evaluator, MulInplace,
                         Ciphertext, a, Plaintext, p),
             evaluator_ptr_);
}

DEFINE_INVOKE_METHOD_RET_1(Ciphertext, Negate);
DEFINE_INVOKE_METHOD_VOID_1(NegateInplace);

Ciphertext Evaluator::Negate(const Ciphertext &a) const {
  return std::visit(
      HE_DISPATCH(DO_INVOKE_METHOD_RET_1, Evaluator, Negate, Ciphertext, a),
      evaluator_ptr_);
}

void Evaluator::NegateInplace(Ciphertext *a) const {
  std::visit(HE_DISPATCH(DO_INVOKE_METHOD_VOID_1, Evaluator, NegateInplace,
                         Ciphertext, a),
             evaluator_ptr_);
}

SchemaType Evaluator::GetSchemaType() const { return schema_type_; }

}  // namespace heu::lib::phe
