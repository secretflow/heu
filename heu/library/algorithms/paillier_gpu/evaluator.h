// Copyright 2023 Ant Group Co., Ltd.
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

#include "heu/library/algorithms/paillier_gpu/ciphertext.h"
#include "heu/library/algorithms/paillier_gpu/encryptor.h"
#include "heu/library/algorithms/paillier_gpu/public_key.h"

namespace heu::lib::algorithms::paillier_g {

class Evaluator {
 public:
  explicit Evaluator(const PublicKey& pk) : pk_(pk), encryptor_(pk) {}

  // The performance of Randomize() is exactly the same as that of Encrypt().
  void Randomize(Span<Ciphertext> ct) const;

  std::vector<Ciphertext> Add(ConstSpan<Ciphertext> ct0,
                              ConstSpan<Ciphertext> ct1) const;
  std::vector<Ciphertext> Add(ConstSpan<Ciphertext> cts,
                              ConstSpan<Plaintext> pts) const;
  std::vector<Ciphertext> Add(ConstSpan<Plaintext> pts,
                              ConstSpan<Ciphertext> cts) const;
  std::vector<Plaintext> Add(ConstSpan<Plaintext> a,
                             ConstSpan<Plaintext> b) const;
  void AddInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const;
  void AddInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const;
  void AddInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

  std::vector<Ciphertext> Sub(ConstSpan<Ciphertext> a,
                              ConstSpan<Ciphertext> b) const;
  std::vector<Ciphertext> Sub(ConstSpan<Ciphertext> a,
                              ConstSpan<Plaintext> b) const;
  std::vector<Ciphertext> Sub(ConstSpan<Plaintext> a,
                              ConstSpan<Ciphertext> b) const;
  std::vector<Plaintext> Sub(ConstSpan<Plaintext> a,
                             ConstSpan<Plaintext> b) const;

  void SubInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const;
  void SubInplace(Span<Ciphertext> a, ConstSpan<Plaintext> p) const;
  void SubInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

  std::vector<Ciphertext> Mul(ConstSpan<Ciphertext> cts,
                              ConstSpan<Plaintext> pts) const;
  std::vector<Ciphertext> Mul(ConstSpan<Plaintext> pts,
                              ConstSpan<Ciphertext> cts) const;
  std::vector<Plaintext> Mul(ConstSpan<Plaintext> pts1,
                             ConstSpan<Plaintext> pts2) const;

  void MulInplace(Span<Ciphertext> cts, ConstSpan<Plaintext> pts) const;
  void MulInplace(Span<Plaintext> pts1, ConstSpan<Plaintext> pts2) const;

  // // out = -a
  std::vector<Ciphertext> Negate(ConstSpan<Ciphertext> a) const;
  void NegateInplace(Span<Ciphertext> a) const;

 private:
  PublicKey pk_;
  Encryptor encryptor_;
};

}  // namespace heu::lib::algorithms::paillier_g
