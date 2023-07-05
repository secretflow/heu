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

#include "heu/library/algorithms/elgamal/ciphertext.h"
#include "heu/library/algorithms/elgamal/plaintext.h"
#include "heu/library/algorithms/elgamal/public_key.h"

namespace heu::lib::algorithms::elgamal {

class Evaluator {
 public:
  explicit Evaluator(const PublicKey& pk);

  void Randomize(Ciphertext* ct) const;

  Ciphertext Add(const Ciphertext& a, const Ciphertext& b) const;
  Ciphertext Add(const Ciphertext& a, const Plaintext& b) const;
  Ciphertext Add(const Plaintext& a, const Ciphertext& b) const;
  Plaintext Add(const Plaintext& a, const Plaintext& b) const;
  void AddInplace(Ciphertext* a, const Ciphertext& b) const;
  void AddInplace(Ciphertext* a, const Plaintext& b) const;
  void AddInplace(Plaintext* a, const Plaintext& b) const;

  Ciphertext Sub(const Ciphertext& a, const Ciphertext& b) const;
  Ciphertext Sub(const Ciphertext& a, const Plaintext& b) const;
  Ciphertext Sub(const Plaintext& a, const Ciphertext& b) const;
  Plaintext Sub(const Plaintext& a, const Plaintext& b) const;
  void SubInplace(Ciphertext* a, const Ciphertext& b) const;
  void SubInplace(Ciphertext* a, const Plaintext& p) const;
  void SubInplace(Plaintext* a, const Plaintext& b) const;

  Ciphertext Mul(const Ciphertext& a, const Plaintext& b) const;
  Ciphertext Mul(const Plaintext& a, const Ciphertext& b) const;
  Plaintext Mul(const Plaintext& a, const Plaintext& b) const;
  void MulInplace(Ciphertext* a, const Plaintext& b) const;
  void MulInplace(Plaintext* a, const Plaintext& b) const;

  // out = -a
  Ciphertext Negate(const Ciphertext& a) const;
  void NegateInplace(Ciphertext* a) const;

 private:
  PublicKey pk_;
  std::shared_ptr<yacl::crypto::EcGroup> ec_;
};

}  // namespace heu::lib::algorithms::elgamal
