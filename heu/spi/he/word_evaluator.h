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

#include "heu/spi/he/base.h"

namespace heu::lib::spi {

class WordEvaluator {
 public:
  virtual ~WordEvaluator() = default;

  //===   Arithmetic Operations   ===//

  /*
   * Item 本质上在 C++ 之上构建了一套无类型系统，类似于
   * Python，任何类型都可以转换成 Item， 反之 Item 也可以变成任何实际类型。
   *
   * 一些缩写约定：
   *   PT => Plaintext
   *   CT => Ciphertext
   *   PTs => Plaintext Array
   *   CTs => Ciphertext Array
   */

  // PT = -PT
  // CT = -CT
  // PTs = -PTs
  // CTs = -CTs
  virtual Item Negate(const Item& a) const = 0;
  virtual void NegateInplace(Item* a) const = 0;

  // PT = PT + PT
  // CT = PT + CT
  // CT = CT + PT
  // CT = CT + CT
  // PTs = PTs + PT [Broadcast]
  // CTs = PTs + CT [Broadcast]
  // CTs = CTs + PT [Broadcast]
  // CTs = CTs + CT [Broadcast]
  // PTs = PT + PTs [Broadcast]
  // CTs = PT + CTs [Broadcast]
  // CTs = CT + PTs [Broadcast]
  // CTs = CT + CTs [Broadcast]
  // PTs = PTs + PTs
  // CTs = PTs + CTs
  // CTs = CTs + PTs
  // CTs = CTs + CTs
  virtual Item Add(const Item& a, const Item& b) const = 0;
  // CT += PT
  // CT += CT
  // CTs += PT [Broadcast]
  // CTs += CT [Broadcast]
  // CTs += PTs
  // CTs += CTs
  virtual void AddInplace(Item* a, const Item& b) const = 0;

  // 参数可能的组合类型与 Add 相同
  virtual Item Sub(const Item& a, const Item& b) const = 0;
  virtual void SubInplace(Item* a, const Item& b) const = 0;

  // PT = PT * PT [AHE/FHE]
  // CT = PT * CT [AHE/FHE]
  // CT = CT * PT [AHE/FHE]
  // CT = CT * CT [FHE]
  // PTs = PTs * PT [Broadcast] [AHE/FHE]
  // CTs = PTs * CT [Broadcast] [AHE/FHE]
  // CTs = CTs * PT [Broadcast] [AHE/FHE]
  // CTs = CTs * CT [Broadcast] [FHE]
  // PTs = PT * PTs [Broadcast] [AHE/FHE]
  // CTs = PT * CTs [Broadcast] [AHE/FHE]
  // CTs = CT * PTs [Broadcast] [AHE/FHE]
  // CTs = CT * CTs [Broadcast] [FHE]
  // PTs = PTs * PTs [AHE/FHE]
  // CTs = PTs * CTs [AHE/FHE]
  // CTs = CTs * PTs [AHE/FHE]
  // CTs = CTs * CTs [FHE]
  virtual Item Mul(const Item& a, const Item& b) const = 0;
  virtual void MulInplace(Item* a, const Item& b) const = 0;

  virtual Item Square(const Item& a) const = 0;
  virtual void SquareInplace(Item* a) const = 0;

  virtual Item Pow(const Item& a, int64_t exponent) const = 0;
  virtual void PowInplace(Item* a, int64_t exponent) const = 0;

  //===   Ciphertext maintains   ===//

  // CT -> CT
  // CTs -> CTs
  // The result is same with ct += Enc(0)
  virtual void Randomize(Item* ct) const = 0;

  virtual Item Relinearize(const Item& a) const = 0;
  virtual void RelinearizeInplace(Item* a) const = 0;

  // Given a ciphertext with modulo q_1...q_k, this function switches the
  // modulus down to q_1...q_{k-1}
  virtual Item ModSwitch(const Item& a) const = 0;
  virtual void ModSwitchInplace(Item* a) const = 0;

  // Given a ciphertext with modulo q_1...q_k, this function switches the
  // modulus down to q_1...q_{k-1}, and scales the message down accordingly
  virtual Item Rescale(const Item& a) const = 0;
  virtual void RescaleInplace(Item* a) const = 0;

  //===   Galois automorphism   ===//

  // BFV/BGV only
  virtual Item SwapRows(const Item& a) const = 0;
  virtual void SwapRowsInplace(Item* a) const = 0;

  // CKKS only, for complex number
  virtual Item Conjugate(const Item& a) const = 0;
  virtual void ConjugateInplace(Item* a) const = 0;

  // BFV/BGV batching mode:
  //   The size of matrix is 2-by-(N/2), so move each row cyclically to the left
  //   (steps > 0) or to the right (steps < 0)
  // CKKS batching mode:
  //   rotates the encrypted plaintext vector cyclically to the left (steps > 0)
  //   or to the right (steps < 0).
  // All schemas: require abs(steps) < N/2
  virtual Item Rotate(const Item& a, int steps) const = 0;
  virtual void RotateInplace(Item* a, int steps) const = 0;
};

}  // namespace heu::lib::spi
