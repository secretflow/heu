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

#include "heu/spi/he/sketches/scalar/word_evaluator.h"

namespace heu::lib::spi {

template <typename PlaintextT, typename CiphertextT>
class PheWordEvaluatorScalarSketch
    : public WordEvaluatorScalarSketch<PlaintextT, CiphertextT> {
 public:
  //===   Arithmetic Operations   ===//

  CiphertextT Mul(const CiphertextT&, const CiphertextT&) const override {
    YACL_THROW(
        "Phe schema does not support ciphertext multiplication, please switch "
        "to FHE schemas");
  }

  void MulInplace(CiphertextT*, const CiphertextT&) const override {
    YACL_THROW(
        "Phe schema does not support ciphertext multiplication, please switch "
        "to FHE schemas");
  }

  CiphertextT Square(const CiphertextT&) const override {
    YACL_THROW(
        "Phe schema does not support ciphertext square, please switch to FHE "
        "schemas");
  }

  void SquareInplace(CiphertextT*) const override {
    YACL_THROW(
        "Phe schema does not support ciphertext square, please switch to FHE "
        "schemas");
  }

  CiphertextT Pow(const CiphertextT&, int64_t) const override {
    YACL_THROW(
        "Phe schema does not support ciphertext pow, please switch to FHE "
        "schemas");
  }

  void PowInplace(CiphertextT*, int64_t) const override {
    YACL_THROW(
        "Phe schema does not support ciphertext pow, please switch to FHE "
        "schemas");
  }

  //===   FHE only operations   ===//

  CiphertextT Relinearize(const CiphertextT& a) const override {
    return a;  // nothing to do
  }

  void RelinearizeInplace(CiphertextT*) const override {}  // nothing to do

  CiphertextT ModSwitch(const CiphertextT&) const override {
    YACL_THROW(
        "Phe schema does not support modulus switch, please switch to FHE "
        "schemas");
  }

  void ModSwitchInplace(CiphertextT*) const override {
    YACL_THROW(
        "Phe schema does not support modulus switch, please switch to FHE "
        "schemas");
  }

  CiphertextT Rescale(const CiphertextT&) const override {
    YACL_THROW(
        "Phe schema does not support rescaling, please switch to FHE schemas");
  }

  void RescaleInplace(CiphertextT*) const override {
    YACL_THROW(
        "Phe schema does not support rescaling, please switch to FHE schemas");
  }

  CiphertextT SwapRows(const CiphertextT&) const override {
    YACL_THROW(
        "Phe schema does not support swap rows, please switch to FHE schemas");
  }

  void SwapRowsInplace(CiphertextT*) const override {
    YACL_THROW(
        "Phe schema does not support swap rows, please switch to FHE schemas");
  }

  CiphertextT Conjugate(const CiphertextT&) const override {
    YACL_THROW(
        "Phe schema does not support conjugate, please switch to FHE schemas");
  }

  void ConjugateInplace(CiphertextT*) const override {
    YACL_THROW(
        "Phe schema does not support conjugate, please switch to FHE schemas");
  }

  CiphertextT Rotate(const CiphertextT&, int) const override {
    YACL_THROW(
        "Phe schema does not support rotating, please switch to FHE schemas");
  }

  void RotateInplace(CiphertextT*, int) const override {
    YACL_THROW(
        "Phe schema does not support rotating, please switch to FHE schemas");
  }
};

}  // namespace heu::lib::spi
