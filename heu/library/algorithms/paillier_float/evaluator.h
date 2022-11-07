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

#include "heu/library/algorithms/paillier_float/ciphertext.h"
#include "heu/library/algorithms/paillier_float/encryptor.h"
#include "heu/library/algorithms/paillier_float/public_key.h"

namespace heu::lib::algorithms::paillier_f {

class Evaluator {
 public:
  explicit Evaluator(const PublicKey& pk) : pk_(pk), encryptor_(pk) {}

 public:
  void Randomize(Ciphertext* ct) const;

  // c = a + b
  Ciphertext Add(const Ciphertext& a, const Ciphertext& b) const;
  Ciphertext Add(const Ciphertext& a, const MPInt& b) const;
  Ciphertext Add(const Ciphertext& a, double b) const;
  Plaintext Add(const Plaintext& a, const Plaintext& b) const { return a + b; };
  Ciphertext Add(const Plaintext& a, const Ciphertext& b) const {
    return Add(b, a);
  }

  // a = a + b
  void AddInplace(Ciphertext* a, const Ciphertext& b) const;
  void AddInplace(Ciphertext* a, const MPInt& b) const;
  void AddInplace(Ciphertext* a, double b) const;
  void AddInplace(Plaintext* a, const Plaintext& b) const { *a += b; }

  // out = a - b
  Ciphertext Sub(const Ciphertext& a, const Ciphertext& b) const;
  Ciphertext Sub(const Ciphertext& a, const MPInt& b) const;
  Ciphertext Sub(const MPInt& a, const Ciphertext& b) const;
  Plaintext Sub(const Plaintext& a, const Plaintext& b) const { return a - b; };
  // a -= b
  void SubInplace(Ciphertext* a, const Ciphertext& b) const;
  void SubInplace(Ciphertext* a, const MPInt& b) const;
  void SubInplace(Plaintext* a, const Plaintext& b) const { *a -= b; }

  // c = a * b
  Ciphertext Mul(const Ciphertext& a, const MPInt& b) const;
  Ciphertext Mul(const Ciphertext& a, double b) const;
  Plaintext Mul(const Plaintext& a, const Plaintext& b) const { return a * b; };
  Ciphertext Mul(const Plaintext& a, const Ciphertext& b) const {
    return Mul(b, a);
  }

  // a = a * b
  void MulInplace(Ciphertext* a, const MPInt& b) const;
  void MulInplace(Ciphertext* a, double b) const;
  void MulInplace(Plaintext* a, const Plaintext& b) const { *a *= b; };

  // b = -a
  Ciphertext Negate(const Ciphertext& a) const;
  // a = -a
  void NegateInplace(Ciphertext* a) const;

 private:
  MPInt AddRaw(const MPInt& a, const MPInt& b) const;

  MPInt MulRaw(const MPInt& a, const MPInt& b) const;

  /// decrease cipher's exponent to new_exp
  /// if new_exp > cipher's exponent, raise exception.
  /// @param [in,out] cipher
  void DecreaseExponentTo(Ciphertext* cipher, int new_exp) const;

 private:
  PublicKey pk_;
  Encryptor encryptor_;
};

}  // namespace heu::lib::algorithms::paillier_f
