// Copyright 2023 Denglin Co., Ltd.
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

#include "heu/library/algorithms/paillier_dl/ciphertext.h"
#include "heu/library/algorithms/paillier_dl/encryptor.h"
#include "heu/library/algorithms/paillier_dl/public_key.h"

namespace heu::lib::algorithms::paillier_dl {

class Evaluator {
 public:
  explicit Evaluator(const PublicKey& pk) : pk_(pk), encryptor_(pk) {}

  // The performance of Randomize() is exactly the same as that of Encrypt().
  void Randomize(Ciphertext* ct) const;

  // out = a + b
  // Warning: if a, b are in batch encoding form, then p must also be in batch
  // encoding form
  std::vector<Ciphertext> Add(const std::vector<Ciphertext>& as, const std::vector<Ciphertext>& bs) const;
  std::vector<Ciphertext> Add(const std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const;
  std::vector<Plaintext> Add(const std::vector<Plaintext>& as, const std::vector<Plaintext>& bs) const { 
    std::vector<Plaintext> outs;
    for (int i=0; i<as.size(); i++) {
      outs.emplace_back(as[i] + bs[i]);
    }
    return outs;
  }
  std::vector<Ciphertext> Add(const std::vector<Plaintext>& as, const std::vector<Ciphertext>& bs) const {
    return Add(bs, as);
  }

  void AddInplace(std::vector<Ciphertext>& as, const std::vector<Ciphertext>& bs) const;
  void AddInplace(std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const;
  void AddInplace(std::vector<Plaintext>& as, const std::vector<Plaintext>& bs) const {
    for (int i=0; i<as.size(); i++) {
      as[i] += bs[i];
    }
  }

  // out = a - b
  // Warning: Subtraction is not supported if a, b are in batch encoding
  std::vector<Ciphertext> Sub(const std::vector<Ciphertext>& as, const std::vector<Ciphertext>& bs) const;
  std::vector<Ciphertext> Sub(const std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const;
  std::vector<Plaintext> Sub(const std::vector<Plaintext>& as, const std::vector<Plaintext>& bs) const { 
    std::vector<Plaintext> outs;
    for (int i=0; i<as.size(); i++) {
      outs.emplace_back(as[i] - bs[i]);
    }
    return outs;
  };
  std::vector<Ciphertext> Sub(const std::vector<Plaintext>& as, const std::vector<Ciphertext>& bs) const { 
    return Sub(bs, as);
  }

  void SubInplace(std::vector<Ciphertext>& as, const std::vector<Ciphertext>& bs) const;
  void SubInplace(std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const;
  void SubInplace(std::vector<Plaintext>& as, const std::vector<Plaintext>& bs) const { 
    for (int i=0; i<as.size(); i++) {
      as[i] -= bs[i];
    }
  }

  // out = a * p
  // Warning 1:
  // When p = 0, the result is insecure and cannot be sent directly to the peer
  // and must call Randomize(&out) first to obfuscate out.
  // If a * 0 is not the last operation, (out will continue to participate in
  // subsequent operations), Randomize can be omitted.
  // Warning 2:
  // Multiplication is not supported if a is in batch encoding form
  std::vector<Ciphertext> Mul(const std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const;
  std::vector<Plaintext> Mul(const std::vector<Plaintext>& as, const std::vector<Plaintext>& bs) const {
    std::vector<Plaintext> outs;
    for (int i=0; i<as.size(); i++) {
      outs.emplace_back(as[i] * bs[i]);
    }
    return outs;
  };
  std::vector<Ciphertext> Mul(const std::vector<Plaintext>& as, const std::vector<Ciphertext>& bs) const {
    return Mul(bs, as);
  }

  void MulInplace(std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const;
  void MulInplace(Plaintext* a, const Plaintext& b) const { *a *= b; };

  // out = -a
  std::vector<Ciphertext> Negate(const std::vector<Ciphertext>& as) const;
  void NegateInplace(std::vector<Ciphertext>& as) const;

 private:
  std::vector<Plaintext> HandleNeg(const std::vector<Plaintext>& as) const {
    std::vector<Plaintext> handled_as;
    for (int i=0; i<as.size(); i++) {
      MPInt tmp_a(as[i]);
      if (tmp_a.IsNegative()) {
        tmp_a += pk_.n_;
      }
      handled_as.push_back(tmp_a);
    }
    return handled_as;
  }

 private:
  PublicKey pk_;
  Encryptor encryptor_;
};

}  // namespace heu::lib::algorithms::paillier_dl
