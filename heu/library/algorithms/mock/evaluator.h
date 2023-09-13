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

#include "heu/library/algorithms/mock/ciphertext.h"
#include "heu/library/algorithms/mock/encryptor.h"
#include "heu/library/algorithms/mock/plaintext.h"
#include "heu/library/algorithms/mock/public_key.h"
#include "heu/library/algorithms/mock/switch_spi.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::mock {

class Evaluator {
 public:
  // [SPI: Critical]
  explicit Evaluator(const PublicKey& pk) : pk_(pk), encryptor_(pk) {}

// To algorithm developers:
// The Evaluator class supports two different interfaces:
// IMPL_SCALAR_SPI and IMPL_VECTORIZED_SPI. You only need to choose either SPI
// to implementation, you can completely remove the other SPI, including
// function declaration and function implementation.
// Please see switch_spi.h for details.
#ifdef IMPL_SCALAR_SPI
  // [SPI: Critical]
  void Randomize(Ciphertext* ct) const;

  // [SPI: Critical]
  Ciphertext Add(const Ciphertext& a, const Ciphertext& b) const;
  // [SPI: Critical]
  Ciphertext Add(const Ciphertext& a, const Plaintext& b) const;
  // [SPI: Critical]
  Ciphertext Add(const Plaintext& a, const Ciphertext& b) const;
  // [SPI: Important]
  Plaintext Add(const Plaintext& a, const Plaintext& b) const;

  // [SPI: Critical]
  void AddInplace(Ciphertext* a, const Ciphertext& b) const;
  // [SPI: Critical]
  void AddInplace(Ciphertext* a, const Plaintext& b) const;
  // [SPI: Important]
  void AddInplace(Plaintext* a, const Plaintext& b) const;

  // [SPI: Critical]
  Ciphertext Sub(const Ciphertext& a, const Ciphertext& b) const;
  // [SPI: Critical]
  Ciphertext Sub(const Ciphertext& a, const Plaintext& b) const;
  // [SPI: Critical]
  Ciphertext Sub(const Plaintext& a, const Ciphertext& b) const;
  // [SPI: Important]
  Plaintext Sub(const Plaintext& a, const Plaintext& b) const;

  // [SPI: Critical]
  void SubInplace(Ciphertext* a, const Ciphertext& b) const;
  // [SPI: Critical]
  void SubInplace(Ciphertext* a, const Plaintext& p) const;
  // [SPI: Important]
  void SubInplace(Plaintext* a, const Plaintext& b) const;

  // [SPI: Critical]
  Ciphertext Mul(const Ciphertext& a, const Plaintext& b) const;
  // [SPI: Critical]
  Ciphertext Mul(const Plaintext& a, const Ciphertext& b) const;
  // [SPI: Important]
  Plaintext Mul(const Plaintext& a, const Plaintext& b) const;

  // [SPI: Critical]
  void MulInplace(Ciphertext* a, const Plaintext& b) const;
  // [SPI: Important]
  void MulInplace(Plaintext* a, const Plaintext& b) const;

  // out = -a
  Ciphertext Negate(const Ciphertext& a) const;  // [SPI: Critical]
  void NegateInplace(Ciphertext* a) const;       // [SPI: Critical]
#endif

#ifdef IMPL_VECTORIZED_SPI
  void Randomize(Span<Ciphertext> ct) const;

  // [SPI: Critical]
  std::vector<Ciphertext> Add(ConstSpan<Ciphertext> a,
                              ConstSpan<Ciphertext> b) const;
  // [SPI: Critical]
  std::vector<Ciphertext> Add(ConstSpan<Ciphertext> a,
                              ConstSpan<Plaintext> b) const;
  // [SPI: Critical]
  std::vector<Ciphertext> Add(ConstSpan<Plaintext> a,
                              ConstSpan<Ciphertext> b) const;
  // [SPI: Important]
  std::vector<Plaintext> Add(ConstSpan<Plaintext> a,
                             ConstSpan<Plaintext> b) const;

  // [SPI: Critical]
  void AddInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const;
  // [SPI: Critical]
  void AddInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const;
  // [SPI: Important]
  void AddInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

  // [SPI: Critical]
  std::vector<Ciphertext> Sub(ConstSpan<Ciphertext> a,
                              ConstSpan<Ciphertext> b) const;
  // [SPI: Critical]
  std::vector<Ciphertext> Sub(ConstSpan<Ciphertext> a,
                              ConstSpan<Plaintext> b) const;
  // [SPI: Critical]
  std::vector<Ciphertext> Sub(ConstSpan<Plaintext> a,
                              ConstSpan<Ciphertext> b) const;
  // [SPI: Important]
  std::vector<Plaintext> Sub(ConstSpan<Plaintext> a,
                             ConstSpan<Plaintext> b) const;

  // [SPI: Critical]
  void SubInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const;
  // [SPI: Critical]
  void SubInplace(Span<Ciphertext> a, ConstSpan<Plaintext> p) const;
  // [SPI: Important]
  void SubInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

  // [SPI: Critical]
  std::vector<Ciphertext> Mul(ConstSpan<Ciphertext> a,
                              ConstSpan<Plaintext> b) const;
  // [SPI: Critical]
  std::vector<Ciphertext> Mul(ConstSpan<Plaintext> a,
                              ConstSpan<Ciphertext> b) const;
  // [SPI: Important]
  std::vector<Plaintext> Mul(ConstSpan<Plaintext> a,
                             ConstSpan<Plaintext> b) const;

  // [SPI: Critical]
  void MulInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const;
  // [SPI: Important]
  void MulInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

  // out = -a
  // [SPI: Critical]
  std::vector<Ciphertext> Negate(ConstSpan<Ciphertext> a) const;
  void NegateInplace(Span<Ciphertext> a) const;  // [SPI: Critical]

#endif

 private:
  PublicKey pk_;
  Encryptor encryptor_;
};

}  // namespace heu::lib::algorithms::mock
