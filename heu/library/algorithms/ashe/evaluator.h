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

#include "heu/library/algorithms/ashe/ciphertext.h"
#include "heu/library/algorithms/ashe/public_parameters.h"

namespace heu::lib::algorithms::ashe {
class Evaluator {
 public:
  explicit Evaluator(PublicParameters pp) : pp_(std::move(pp)) {}

  void Randomize(Ciphertext *ct) const;

  [[nodiscard]] Ciphertext Add(const Ciphertext &a, const Ciphertext &b) const;
  [[nodiscard]] Ciphertext Add(const Ciphertext &a, const Plaintext &b) const;
  [[nodiscard]] Ciphertext Add(const Plaintext &a, const Ciphertext &b) const;
  [[nodiscard]] Plaintext Add(const Plaintext &a, const Plaintext &b) const;

  void AddInplace(Ciphertext *a, const Ciphertext &b) const;
  void AddInplace(Ciphertext *a, const Plaintext &b) const;
  void AddInplace(Plaintext *a, const Plaintext &b) const;

  [[nodiscard]] Ciphertext Sub(const Ciphertext &a, const Ciphertext &b) const;
  [[nodiscard]] Ciphertext Sub(const Ciphertext &a, const Plaintext &b) const;
  [[nodiscard]] Ciphertext Sub(const Plaintext &a, const Ciphertext &b) const;
  [[nodiscard]] Plaintext Sub(const Plaintext &a, const Plaintext &b) const;

  void SubInplace(Ciphertext *a, const Ciphertext &b) const;
  void SubInplace(Ciphertext *a, const Plaintext &p) const;
  void SubInplace(Plaintext *a, const Plaintext &b) const;

  [[nodiscard]] Ciphertext Mul(const Ciphertext &a, const Plaintext &b) const;
  [[nodiscard]] Ciphertext Mul(const Plaintext &a, const Ciphertext &b) const;
  [[nodiscard]] Plaintext Mul(const Plaintext &a, const Plaintext &b) const;

  void MulInplace(Ciphertext *a, const Plaintext &b) const;
  void MulInplace(Plaintext *a, const Plaintext &b) const;

  [[nodiscard]] Ciphertext Negate(const Ciphertext &a) const;
  void NegateInplace(Ciphertext *a) const;

 private:
  PublicParameters pp_;
  BigInt ONE = BigInt(1);
  BigInt ZERO = BigInt(0);
  BigInt MAX = BigInt(UINT64_MAX);
  BigInt PlainSpace = BigInt(2).Pow(16);
};
}  // namespace heu::lib::algorithms::ashe
