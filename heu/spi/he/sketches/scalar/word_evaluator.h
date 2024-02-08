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

// ================================================================ //
// <<<              Sketch 接口与 SPI 接口基本类似                 >>> //
// <<<            此处仅以 WordEvaluator 为例展示接口              >>> //
// <<<    Word/Gate/Binary Evaluator 接口变化同理，此处不再展开     >>> //
// ================================================================ //

#include <cstdint>

#include "heu/spi/he/sketches/scalar/helpful_macros.h"
#include "heu/spi/he/word_evaluator.h"

namespace heu::lib::spi {

template <typename PlaintextT, typename CiphertextT>
class WordEvaluatorScalarSketch : public WordEvaluator {
 public:
  virtual ~WordEvaluatorScalarSketch() = default;

  //===   Arithmetic Operations   ===//

  // PT = -PT
  // CT = -CT
  virtual PlaintextT Negate(const PlaintextT& a) const = 0;
  virtual void NegateInplace(PlaintextT* a) const = 0;
  virtual CiphertextT Negate(const CiphertextT& a) const = 0;
  virtual void NegateInplace(CiphertextT* a) const = 0;

  // PT = PT + PT
  // CT = PT + CT
  // CT = CT + PT
  // CT = CT + CT
  virtual PlaintextT Add(const PlaintextT& a, const PlaintextT& b) const = 0;
  virtual CiphertextT Add(const CiphertextT& a, const PlaintextT& b) const = 0;
  virtual CiphertextT Add(const CiphertextT& a, const CiphertextT& b) const = 0;

  virtual CiphertextT Add(const PlaintextT& a, const CiphertextT& b) const {
    return Add(b, a);
  }

  // CT += PT
  // CT += CT
  virtual void AddInplace(CiphertextT* a, const PlaintextT& b) const = 0;
  virtual void AddInplace(CiphertextT* a, const CiphertextT& b) const = 0;

  // PT = PT - PT
  // CT = PT - CT
  // CT = CT - PT
  // CT = CT - CT
  virtual PlaintextT Sub(const PlaintextT& a, const PlaintextT& b) const {
    return Add(a, Negate(b));
  }

  virtual CiphertextT Sub(const PlaintextT& a, const CiphertextT& b) const {
    return Add(Negate(b), a);
  }

  virtual CiphertextT Sub(const CiphertextT& a, const PlaintextT& b) const {
    return Add(a, Negate(b));
  }

  virtual CiphertextT Sub(const CiphertextT& a, const CiphertextT& b) const {
    return Add(a, Negate(b));
  }

  // CT -= PT
  // CT -= CT
  virtual void SubInplace(CiphertextT* a, const PlaintextT& b) const {
    AddInplace(a, Negate(b));
  }

  virtual void SubInplace(CiphertextT* a, const CiphertextT& b) const {
    AddInplace(a, Negate(b));
  }

  // PT = PT * PT [AHE/FHE]
  // CT = PT * CT [AHE/FHE]
  // CT = CT * PT [AHE/FHE]
  // CT = CT * CT [FHE]
  virtual PlaintextT Mul(const PlaintextT& a, const PlaintextT& b) const = 0;
  virtual CiphertextT Mul(const CiphertextT& a, const PlaintextT& b) const = 0;
  virtual CiphertextT Mul(const CiphertextT& a, const CiphertextT& b) const = 0;

  virtual CiphertextT Mul(const PlaintextT& a, const CiphertextT& b) const {
    return Mul(b, a);
  }

  // CT *= PT [AHE/FHE]
  // CT *= CT [FHE]
  virtual void MulInplace(CiphertextT* a, const PlaintextT& b) const = 0;
  virtual void MulInplace(CiphertextT* a, const CiphertextT& b) const = 0;

  virtual PlaintextT Square(const PlaintextT& a) const = 0;
  virtual CiphertextT Square(const CiphertextT& a) const = 0;
  virtual void SquareInplace(PlaintextT* a) const = 0;
  virtual void SquareInplace(CiphertextT* a) const = 0;

  virtual PlaintextT Pow(const PlaintextT& a, int64_t exponent) const = 0;
  virtual CiphertextT Pow(const CiphertextT& a, int64_t exponent) const = 0;
  virtual void PowInplace(PlaintextT* a, int64_t exponent) const = 0;
  virtual void PowInplace(CiphertextT* a, int64_t exponent) const = 0;

  //===   Ciphertext maintains   ===//

  // CT -> CT
  // The result is same with ct += Enc(0)
  virtual void Randomize(CiphertextT* ct) const = 0;

  virtual CiphertextT Relinearize(const CiphertextT& a) const = 0;
  virtual void RelinearizeInplace(CiphertextT* a) const = 0;

  // Given a ciphertext with modulo q_1...q_k, this function switches the
  // modulus down to q_1...q_{k-1}
  virtual CiphertextT ModSwitch(const CiphertextT& a) const = 0;
  virtual void ModSwitchInplace(CiphertextT* a) const = 0;

  // Given a ciphertext with modulo q_1...q_k, this function switches the
  // modulus down to q_1...q_{k-1}, and scales the message down accordingly
  virtual CiphertextT Rescale(const CiphertextT& a) const = 0;
  virtual void RescaleInplace(CiphertextT* a) const = 0;

  //===   Galois automorphism   ===//

  // BFV/BGV only
  virtual CiphertextT SwapRows(const CiphertextT& a) const = 0;
  virtual void SwapRowsInplace(CiphertextT* a) const = 0;

  // CKKS only, for complex number
  virtual CiphertextT Conjugate(const CiphertextT& a) const = 0;
  virtual void ConjugateInplace(CiphertextT* a) const = 0;

  // BFV/BGV batching mode:
  //   The size of matrix is 2-by-(N/2), so move each row cyclically to the left
  //   (steps > 0) or to the right (steps < 0)
  // CKKS batching mode:
  //   rotates the encrypted plaintext vector cyclically to the left (steps > 0)
  //   or to the right (steps < 0).
  // All schemas: require abs(steps) < N/2
  virtual CiphertextT Rotate(const CiphertextT& a, int steps) const = 0;
  virtual void RotateInplace(CiphertextT* a, int steps) const = 0;

 private:
  //===   Arithmetic Operations   ===//

  DefineUnaryFuncBoth(Negate);
  DefineUnaryInplaceFunc(NegateInplace);

  DefineBinaryFunc(Add);
  DefineBinaryInplaceFunc(AddInplace);

  DefineBinaryFunc(Sub);
  DefineBinaryInplaceFunc(SubInplace);

  DefineBinaryFunc(Mul);
  DefineBinaryInplaceFunc(MulInplace);

  DefineUnaryFuncBoth(Square);
  DefineUnaryInplaceFunc(SquareInplace);

  Item Pow(const Item& x, int64_t exponent) const override {
    if (x.IsCiphertext()) {
      CallUnaryFunc(Pow, CiphertextT, x, exponent);
    } else {
      CallUnaryFunc(Pow, PlaintextT, x, exponent);
    }
  }

  void PowInplace(Item* x, int64_t exponent) const override {
    if (x->IsCiphertext()) {
      CallUnaryInplaceFunc(PowInplace, CiphertextT, x, exponent);
    } else {
      CallUnaryInplaceFunc(PowInplace, PlaintextT, x, exponent);
    }
  }

  //===   Ciphertext maintains   ===//

  DefineUnaryInplaceFuncOnlyCipher(Randomize);

  DefineUnaryFuncCT(Relinearize);
  DefineUnaryInplaceFuncOnlyCipher(RelinearizeInplace);

  DefineUnaryFuncCT(ModSwitch);
  DefineUnaryInplaceFuncOnlyCipher(ModSwitchInplace);

  DefineUnaryFuncCT(Rescale);
  DefineUnaryInplaceFuncOnlyCipher(RescaleInplace);

  //===   Galois automorphism   ===//

  DefineUnaryFuncCT(SwapRows);
  DefineUnaryInplaceFuncOnlyCipher(SwapRowsInplace);

  DefineUnaryFuncCT(Conjugate);
  DefineUnaryInplaceFuncOnlyCipher(ConjugateInplace);

  Item Rotate(const Item& x, int steps) const override {
    YACL_ENFORCE(x.IsCiphertext(), "input arg must be a cipher, real is {}",
                 x.ToString());
    CallUnaryFunc(Rotate, CiphertextT, x, steps);
  }

  void RotateInplace(Item* x, int steps) const override {
    YACL_ENFORCE(x->IsCiphertext(), "input arg must be a cipher, real is {}",
                 x->ToString());
    CallUnaryInplaceFunc(RotateInplace, CiphertextT, x, steps);
  }
};

}  // namespace heu::lib::spi
