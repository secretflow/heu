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

#pragma once

#include <cstdint>
#include <vector>

#include "absl/types/span.h"

// ================================================================ //
// <<<              Sketch 接口与 SPI 接口基本类似                 >>> //
// <<<            此处仅以 WordEvaluator 为例展示接口              >>> //
// <<< 其它 Encryptor/Evaluator/Decryptor 接口变化同理，此处不再展开 >>> //
// ================================================================ //

namespace heu::lib::spi {

template <typename PlaintextT, typename CiphertextT>
class WordEvaluatorVectorSketch {
 public:
  virtual ~WordEvaluatorVectorSketch() = default;

  //===   Arithmetic Operations   ===//

  // PT = -PT
  // CT = -CT
  virtual std::vector<PlaintextT> Negate(
      const absl::Span<const PlaintextT>& a) const = 0;
  virtual void NegateInplace(absl::Span<PlaintextT> a) const = 0;
  virtual std::vector<CiphertextT> Negate(
      const absl::Span<const CiphertextT>& a) const = 0;
  virtual void NegateInplace(absl::Span<CiphertextT> a) const = 0;

  // PT = PT + PT
  // CT = PT + CT
  // CT = CT + PT
  // CT = CT + CT
  virtual std::vector<PlaintextT> Add(
      const absl::Span<const PlaintextT>& a,
      const absl::Span<const PlaintextT>& b) const = 0;
  virtual std::vector<CiphertextT> Add(
      const absl::Span<const PlaintextT>& a,
      const absl::Span<const CiphertextT>& b) const = 0;
  virtual std::vector<CiphertextT> Add(
      const absl::Span<const CiphertextT>& a,
      const absl::Span<const PlaintextT>& b) const = 0;
  virtual std::vector<CiphertextT> Add(
      const absl::Span<const CiphertextT>& a,
      const absl::Span<const CiphertextT>& b) const = 0;
  // CT += PT
  // CT += CT
  virtual void AddInplace(absl::Span<CiphertextT> a,
                          const absl::Span<const PlaintextT>& b) const = 0;
  virtual void AddInplace(absl::Span<CiphertextT> a,
                          const absl::Span<const CiphertextT>& b) const = 0;

  // PT = PT + PT
  // CT = PT + CT
  // CT = CT + PT
  // CT = CT + CT
  // CT += PT
  // CT += CT
  virtual std::vector<PlaintextT> Sub(
      const absl::Span<const PlaintextT>& a,
      const absl::Span<const PlaintextT>& b) const = 0;
  virtual std::vector<CiphertextT> Sub(
      const absl::Span<const PlaintextT>& a,
      const absl::Span<const CiphertextT>& b) const = 0;
  virtual std::vector<CiphertextT> Sub(
      const absl::Span<const CiphertextT>& a,
      const absl::Span<const PlaintextT>& b) const = 0;
  virtual std::vector<CiphertextT> Sub(
      const absl::Span<const CiphertextT>& a,
      const absl::Span<const CiphertextT>& b) const = 0;
  virtual void SubInplace(absl::Span<CiphertextT> a,
                          const absl::Span<const PlaintextT>& b) const = 0;
  virtual void SubInplace(absl::Span<CiphertextT> a,
                          const absl::Span<const CiphertextT>& b) const = 0;

  // PT = PT * PT [AHE/FHE]
  // CT = PT * CT [AHE/FHE]
  // CT = CT * PT [AHE/FHE]
  // CT = CT * CT [FHE]
  virtual std::vector<PlaintextT> Mul(
      const absl::Span<const PlaintextT>& a,
      const absl::Span<const PlaintextT>& b) const = 0;
  virtual std::vector<CiphertextT> Mul(
      const absl::Span<const PlaintextT>& a,
      const absl::Span<const CiphertextT>& b) const = 0;
  virtual std::vector<CiphertextT> Mul(
      const absl::Span<const CiphertextT>& a,
      const absl::Span<const PlaintextT>& b) const = 0;
  virtual std::vector<CiphertextT> Mul(
      const absl::Span<const CiphertextT>& a,
      const absl::Span<const CiphertextT>& b) const = 0;
  virtual void MulInplace(absl::Span<CiphertextT> a,
                          const absl::Span<const PlaintextT>& b) const = 0;
  virtual void MulInplace(absl::Span<CiphertextT> a,
                          const absl::Span<const CiphertextT>& b) const = 0;

  virtual std::vector<PlaintextT> Square(
      const absl::Span<const PlaintextT>& a) const = 0;
  virtual std::vector<CiphertextT> Square(
      const absl::Span<const CiphertextT>& a) const = 0;
  virtual void SquareInplace(absl::Span<PlaintextT> a) const = 0;
  virtual void SquareInplace(absl::Span<CiphertextT> a) const = 0;

  virtual std::vector<PlaintextT> Pow(const absl::Span<const PlaintextT>& a,
                                      uint64_t exponent) const = 0;
  virtual std::vector<CiphertextT> Pow(const absl::Span<const CiphertextT>& a,
                                       uint64_t exponent) const = 0;
  virtual void PowInplace(absl::Span<PlaintextT> a,
                          uint64_t exponent) const = 0;
  virtual void PowInplace(absl::Span<CiphertextT> a,
                          uint64_t exponent) const = 0;

  //===   Ciphertext maintains   ===//

  // CT -> CT
  // The result is same with ct += Enc(0)
  virtual void Randomize(absl::Span<CiphertextT> ct) const = 0;

  virtual std::vector<CiphertextT> Relinearize(
      const absl::Span<const CiphertextT>& a) const = 0;
  virtual void RelinearizeInplace(absl::Span<CiphertextT> a) const = 0;

  // Given a ciphertext with modulo q_1...q_k, this function switches the
  // modulus down to q_1...q_{k-1}
  virtual std::vector<CiphertextT> ModSwitch(
      const absl::Span<const CiphertextT>& a) const = 0;
  virtual void ModSwitchInplace(absl::Span<CiphertextT> a) const = 0;

  // Given a ciphertext with modulo q_1...q_k, this function switches the
  // modulus down to q_1...q_{k-1}, and scales the message down accordingly
  virtual std::vector<CiphertextT> Rescale(
      const absl::Span<const CiphertextT>& a) const = 0;
  virtual void RescaleInplace(absl::Span<CiphertextT> a) const = 0;

  //===   Galois automorphism   ===//

  // BFV/BGV only
  virtual std::vector<CiphertextT> SwapRows(
      const absl::Span<const CiphertextT>& a) const = 0;
  virtual void SwapRowsInplace(absl::Span<CiphertextT> a) const = 0;

  // CKKS only, for complex number
  virtual std::vector<CiphertextT> Conjugate(
      const absl::Span<const CiphertextT>& a) const = 0;
  virtual void ConjugateInplace(absl::Span<CiphertextT> a) const = 0;

  // BFV/BGV batching mode:
  //   The size of matrix is 2-by-(N/2), so move each row cyclically to the left
  //   (steps > 0) or to the right (steps < 0)
  // CKKS batching mode:
  //   rotates the encrypted plaintext vector cyclically to the left (steps > 0)
  //   or to the right (steps < 0).
  // All schemas: require abs(steps) < N/2
  virtual std::vector<CiphertextT> Rotate(
      const absl::Span<const CiphertextT>& a, int steps) const = 0;
  virtual void RotateInplace(absl::Span<CiphertextT> a, int steps) const = 0;
};

}  // namespace heu::lib::spi
