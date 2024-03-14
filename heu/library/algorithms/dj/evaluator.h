// Copyright 2023 zhangwfjh
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

#include "heu/library/algorithms/dj/ciphertext.h"
#include "heu/library/algorithms/dj/encryptor.h"
#include "heu/library/algorithms/dj/public_key.h"

namespace heu::lib::algorithms::dj {

class Evaluator {
 public:
  explicit Evaluator(const PublicKey &pk) : pk_(pk), encryptor_(pk) {}

  void Randomize(Ciphertext *ct) const;

  Ciphertext Add(const Ciphertext &a, const Ciphertext &b) const;

  Ciphertext Add(const Ciphertext &a, const Plaintext &b) const {
    return Add(a, Ciphertext{pk_.Encrypt(b)});
  }

  Ciphertext Add(const Plaintext &a, const Ciphertext &b) const {
    return Add(b, a);
  }

  Plaintext Add(const Plaintext &a, const Plaintext &b) const { return a + b; }

  void AddInplace(Ciphertext *a, const Ciphertext &b) const { *a = Add(*a, b); }

  void AddInplace(Ciphertext *a, const Plaintext &b) const {
    return AddInplace(a, Ciphertext{pk_.Encrypt(b)});
  }

  void AddInplace(Plaintext *a, const Plaintext &b) const { *a += b; }

  Ciphertext Sub(const Ciphertext &a, const Ciphertext &b) const {
    return Add(a, Negate(b));
  }

  Ciphertext Sub(const Ciphertext &a, const Plaintext &b) const {
    return Add(a, Plaintext{-b});
  }

  Ciphertext Sub(const Plaintext &a, const Ciphertext &b) const {
    return Add(Negate(b), a);
  }

  Plaintext Sub(const Plaintext &a, const Plaintext &b) const { return a - b; }

  void SubInplace(Ciphertext *a, const Ciphertext &b) const {
    AddInplace(a, Negate(b));
  }

  void SubInplace(Ciphertext *a, const Plaintext &b) const {
    AddInplace(a, Plaintext{-b});
  }

  void SubInplace(Plaintext *a, const Plaintext &b) const { *a -= b; }

  Ciphertext Mul(const Ciphertext &a, const Plaintext &p) const;

  Ciphertext Mul(const Plaintext &a, const Ciphertext &b) const {
    return Mul(b, a);
  }

  Plaintext Mul(const Plaintext &a, const Plaintext &b) const { return a * b; }

  void MulInplace(Ciphertext *a, const Plaintext &p) const { *a = Mul(*a, p); }

  void MulInplace(Plaintext *a, const Plaintext &b) const { *a *= b; }

  Ciphertext Negate(const Ciphertext &a) const { return Mul(a, Plaintext{-1}); }

  void NegateInplace(Ciphertext *a) const { *a = Negate(*a); }

 private:
  const PublicKey pk_;
  const Encryptor encryptor_;
};

}  // namespace heu::lib::algorithms::dj
