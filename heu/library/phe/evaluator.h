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

#pragma once

#include <utility>
#include <variant>

#include "heu/library/phe/schema.h"
#include "heu/library/phe/serializable_types.h"
#include "heu/library/phe/variant_helper.h"

namespace heu::lib::phe {

typedef std::variant<HE_NAMESPACE_LIST(Evaluator)> EvaluatorType;

class Evaluator {
 public:
  explicit Evaluator(EvaluatorType evaluator_instance)
      : evaluator_ptr_(std::move(evaluator_instance)) {}

  // The performance of Randomize() is exactly the same as that of Encrypt().
  void Randomize(Ciphertext* ct) const;

  // out = a + b
  Ciphertext Add(const Ciphertext& a, const Ciphertext& b) const;
  void AddInplace(Ciphertext* a, const Ciphertext& b) const;

  // out = a + p
  // Warning: if a, b are in batch encoding form, then p must also be in batch
  // encoding form
  Ciphertext Add(const Ciphertext& a, const Plaintext& p) const;
  Ciphertext Add(const Plaintext& p, const Ciphertext& a) const;
  void AddInplace(Ciphertext* a, const Plaintext& p) const;

  // out = a - b
  // Warning: Subtraction is not supported if a, b are in batch encoding
  Ciphertext Sub(const Ciphertext& a, const Ciphertext& b) const;
  void SubInplace(Ciphertext* a, const Ciphertext& b) const;

  // out = a - p
  Ciphertext Sub(const Ciphertext& a, const Plaintext& p) const;
  // out = p - a
  Ciphertext Sub(const Plaintext& p, const Ciphertext& a) const;
  void SubInplace(Ciphertext* a, const Plaintext& p) const;

  // out = a * p
  // Warning 1:
  // When p = 0, the result is insecure and cannot be sent directly to the peer
  // and must be Randomize(&out) to obfuscate out.
  // If a * 0 is not the last operation, (out will continue to participate in
  // subsequent operations), Randomize can be omitted.
  // Warning 2:
  // Multiplication is not supported if a is in batch encoding form
  Ciphertext Mul(const Ciphertext& a, const Plaintext& p) const;
  Ciphertext Mul(const Plaintext& p, const Ciphertext& a) const;
  void MulInplace(Ciphertext* a, const Plaintext& p) const;

  // out = -a
  Ciphertext Negate(const Ciphertext& a) const;
  void NegateInplace(Ciphertext* a) const;

 private:
  EvaluatorType evaluator_ptr_;
};

}  // namespace heu::lib::phe
