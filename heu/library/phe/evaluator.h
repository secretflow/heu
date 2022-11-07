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

#include "heu/library/phe/base/plaintext.h"
#include "heu/library/phe/base/schema.h"
#include "heu/library/phe/base/serializable_types.h"

namespace heu::lib::phe {

typedef std::variant<HE_NAMESPACE_LIST(Evaluator)> EvaluatorType;

class Evaluator {
 public:
  explicit Evaluator(SchemaType schema_type, EvaluatorType evaluator)
      : schema_type_(schema_type), evaluator_ptr_(std::move(evaluator)) {}

  // The performance of Randomize() is exactly the same as that of Encrypt().
  void Randomize(Ciphertext* ct) const;

  // out = a + b
  // Note: if a, b are in batch encoding form, then p must also be in batch
  // encoding form
  Ciphertext Add(const Ciphertext& a, const Ciphertext& b) const;
  Ciphertext Add(const Ciphertext& a, const Plaintext& p) const;
  Ciphertext Add(const Plaintext& p, const Ciphertext& a) const;
  Plaintext Add(const Plaintext& a, const Plaintext& b) const { return a + b; };
  void AddInplace(Ciphertext* a, const Ciphertext& b) const;
  void AddInplace(Ciphertext* a, const Plaintext& p) const;
  void AddInplace(Plaintext* a, const Plaintext& b) const { *a += b; };

  // out = a - b
  // Warning on batch encoding mode: Subtraction works only if every element in
  // plaintext/ciphertext is positive integer
  Ciphertext Sub(const Ciphertext& a, const Ciphertext& b) const;
  Ciphertext Sub(const Ciphertext& a, const Plaintext& p) const;
  Ciphertext Sub(const Plaintext& p, const Ciphertext& a) const;
  Plaintext Sub(const Plaintext& a, const Plaintext& b) const { return a - b; };
  void SubInplace(Ciphertext* a, const Ciphertext& b) const;
  void SubInplace(Ciphertext* a, const Plaintext& p) const;
  void SubInplace(Plaintext* a, const Plaintext& b) const { *a -= b; };

  // out = a * p
  // Warning 1:
  // When p = 0, the result is insecure and cannot be sent directly to the peer.
  // The result needs to be obfuscated by calling Randomize(&out).
  // If a * 0 is not the last operation, (out will continue to participate in
  // subsequent operations), Randomize can be omitted.
  // Warning 2:
  // Multiplication is not supported if a is in batch encoding form
  Ciphertext Mul(const Ciphertext& a, const Plaintext& p) const;
  Ciphertext Mul(const Plaintext& p, const Ciphertext& a) const;
  Plaintext Mul(const Plaintext& a, const Plaintext& b) const { return a * b; };
  void MulInplace(Ciphertext* a, const Plaintext& p) const;
  void MulInplace(Plaintext* a, const Plaintext& b) const { *a *= b; };

  // out = -a
  Ciphertext Negate(const Ciphertext& a) const;
  Plaintext Negate(const Plaintext& a) const { return -a; };
  void NegateInplace(Ciphertext* a) const;
  void NegateInplace(Plaintext* a) const { a->NegInplace(); };

  SchemaType GetSchemaType() const;

  protected:
  SchemaType schema_type_;
  EvaluatorType evaluator_ptr_;
};

}  // namespace heu::lib::phe
