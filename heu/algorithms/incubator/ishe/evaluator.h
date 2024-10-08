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

#pragma once

#include <cstdint>
#include <memory>

#include "heu/algorithms/incubator/ishe/base.h"
#include "heu/spi/he/sketches/scalar/phe/word_evaluator.h"

namespace heu::algos::ishe {

class Evaluator
    : public spi::PheWordEvaluatorScalarSketch<Plaintext, Ciphertext> {
 public:
  explicit Evaluator(const std::shared_ptr<PublicParameters> &pk) : pp_(pk) {}

  [[nodiscard]] Plaintext Negate(const Plaintext &a) const override;
  void NegateInplace(Plaintext *a) const override;
  [[nodiscard]] Ciphertext Negate(const Ciphertext &a) const override;
  void NegateInplace(Ciphertext *a) const override;

  [[nodiscard]] Plaintext Add(const Plaintext &a,
                              const Plaintext &b) const override;
  [[nodiscard]] Ciphertext Add(const Ciphertext &a,
                               const Plaintext &b) const override;
  [[nodiscard]] Ciphertext Add(const Ciphertext &a,
                               const Ciphertext &b) const override;
  void AddInplace(Ciphertext *a, const Plaintext &b) const override;
  void AddInplace(Ciphertext *a, const Ciphertext &b) const override;

  [[nodiscard]] Plaintext Mul(const Plaintext &a,
                              const Plaintext &b) const override;
  [[nodiscard]] Ciphertext Mul(const Ciphertext &a,
                               const Plaintext &b) const override;
  [[nodiscard]] Ciphertext Mul(const Ciphertext &a,
                               const Ciphertext &b) const override;
  void MulInplace(Ciphertext *a, const Plaintext &b) const override;
  void MulInplace(Ciphertext *a, const Ciphertext &b) const override;

  [[nodiscard]] Plaintext Square(const Plaintext &a) const override;
  void SquareInplace(Plaintext *a) const override;
  [[nodiscard]] Ciphertext Square(const Ciphertext &) const override;
  void SquareInplace(Ciphertext *) const override;
  [[nodiscard]] Plaintext Pow(const Plaintext &a,
                              int64_t exponent) const override;
  void PowInplace(Plaintext *a, int64_t exponent) const override;
  [[nodiscard]] Ciphertext Pow(const Ciphertext &, int64_t) const override;
  void PowInplace(Ciphertext *, int64_t) const override;

  void Randomize(Ciphertext *ct) const override;

 private:
  std::shared_ptr<PublicParameters> pp_;
};

}  // namespace heu::algos::ishe
