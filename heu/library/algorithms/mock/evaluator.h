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
#include "heu/library/algorithms/mock/public_key.h"

namespace heu::lib::algorithms::mock {

class Evaluator {
 public:
  explicit Evaluator(const PublicKey& pk) : pk_(pk), encryptor_(pk) {}

  const Encryptor& GetEncryptor() const { return encryptor_; }

  void Randomize(Ciphertext* ct) const;

  // out = a + b
  Ciphertext Add(const Ciphertext& a, const Ciphertext& b) const;
  void AddInplace(Ciphertext* a, const Ciphertext& b) const;
  // out = a + p
  Ciphertext Add(const Ciphertext& a, const MPInt& p) const;
  void AddInplace(Ciphertext* a, const MPInt& p) const;

  // out = a - b
  Ciphertext Sub(const Ciphertext& a, const Ciphertext& b) const;
  void SubInplace(Ciphertext* a, const Ciphertext& b) const;
  // out = a - p
  Ciphertext Sub(const Ciphertext& a, const MPInt& p) const;
  void SubInplace(Ciphertext* a, const MPInt& p) const;
  // out = p - a
  Ciphertext Sub(const MPInt& p, const Ciphertext& a) const;

  // out = a * p
  Ciphertext Mul(const Ciphertext& a, const MPInt& p) const;
  void MulInplace(Ciphertext* a, const MPInt& p) const;

  // out = -a
  Ciphertext Negate(const Ciphertext& a) const;
  void NegateInplace(Ciphertext* a) const;

 private:
  PublicKey pk_;
  Encryptor encryptor_;
};

}  // namespace heu::lib::algorithms::mock
