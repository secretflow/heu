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

#include "heu/library/algorithms/paillier_zahlen/ciphertext.h"
#include "heu/library/algorithms/paillier_zahlen/encryptor.h"
#include "heu/library/algorithms/paillier_zahlen/public_key.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_z {

class Evaluator {
 public:
  explicit Evaluator(const PublicKey& pk) : pk_(pk), encryptor_(pk) {}

  // The performance of Randomize() is exactly the same as that of Encrypt().
  void Randomize(Ciphertext* ct) const;

  // out = a + b
  // Warning: if a, b are in batch encoding form, then p must also be in batch
  // encoding form
  Ciphertext Add(const Ciphertext& a, const Ciphertext& b) const;
  Ciphertext Add(const Ciphertext& a, const Plaintext& b) const;
  Plaintext Add(const Plaintext& a, const Plaintext& b) const { return a + b; };
  Ciphertext Add(const Plaintext& a, const Ciphertext& b) const {
    return Add(b, a);
  }

  void AddInplace(Ciphertext* a, const Ciphertext& b) const;
  void AddInplace(Ciphertext* a, const Plaintext& p) const;
  void AddInplace(Plaintext* a, const Plaintext& b) const { *a += b; }

  // out = a - b
  // Warning: Subtraction is not supported if a, b are in batch encoding
  Ciphertext Sub(const Ciphertext& a, const Ciphertext& b) const;
  Ciphertext Sub(const Ciphertext& a, const Plaintext& b) const;
  Ciphertext Sub(const Plaintext& a, const Ciphertext& b) const;
  Plaintext Sub(const Plaintext& a, const Plaintext& b) const { return a - b; };

  void SubInplace(Ciphertext* a, const Ciphertext& b) const;
  void SubInplace(Ciphertext* a, const Plaintext& p) const;
  void SubInplace(Plaintext* a, const Plaintext& b) const { *a -= b; }

  // out = a * p
  // Warning 1:
  // When p = 0, the result is insecure and cannot be sent directly to the peer
  // and must call Randomize(&out) first to obfuscate out.
  // If a * 0 is not the last operation, (out will continue to participate in
  // subsequent operations), Randomize can be omitted.
  // Warning 2:
  // Multiplication is not supported if a is in batch encoding form
  Ciphertext Mul(const Ciphertext& a, const MPInt& p) const;
  Plaintext Mul(const Plaintext& a, const Plaintext& b) const { return a * b; };
  Ciphertext Mul(const Plaintext& a, const Ciphertext& b) const {
    return Mul(b, a);
  }

  void MulInplace(Ciphertext* a, const MPInt& p) const;
  void MulInplace(Plaintext* a, const Plaintext& b) const { *a *= b; };

  // out = -a
  Ciphertext Negate(const Ciphertext& a) const;
  void NegateInplace(Ciphertext* a) const;

  // Add cipher input to sum
  void CalcSum(Ciphertext* sum, ConstSpan<Ciphertext> input) const {}
  // Add plain input to sum
  void CalcSum(Plaintext* sum, ConstSpan<Plaintext> input) const {}
  std::string GetSchema() const { return "zpaillier"; }

 private:
  PublicKey pk_;
  Encryptor encryptor_;
};

}  // namespace heu::lib::algorithms::paillier_z
