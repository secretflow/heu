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

  std::vector<Ciphertext> Add(ConstSpan<Ciphertext> as, ConstSpan<Ciphertext> bs) const;
  std::vector<Ciphertext> Add(ConstSpan<Ciphertext> as, ConstSpan<Plaintext> bs) const;
  std::vector<Ciphertext> Add(ConstSpan<Plaintext> as, ConstSpan<Ciphertext> bs) const {
    return Add(bs, as);
  }
  std::vector<Plaintext> Add(ConstSpan<Plaintext> as, ConstSpan<Plaintext> bs) const {
    std::vector<Plaintext> outs;
    for (int i=0; i<as.size(); i++) {
      outs.emplace_back(*as[i] + *bs[i]);
    }
    return outs;
  }

  void AddInplace(Span<Ciphertext> as, ConstSpan<Ciphertext> bs) const;
  void AddInplace(Span<Ciphertext> as, ConstSpan<Plaintext> bs) const;
  void AddInplace(Span<Plaintext> as, ConstSpan<Plaintext> bs) const {
    for (int i=0; i<as.size(); i++) {
      (*as[i]) += (*bs[i]);
    }
  }

  std::vector<Ciphertext> Sub(ConstSpan<Ciphertext> as, ConstSpan<Ciphertext> bs) const;
  std::vector<Ciphertext> Sub(ConstSpan<Ciphertext> as, ConstSpan<Plaintext> bs) const;
  std::vector<Ciphertext> Sub(ConstSpan<Plaintext> as, ConstSpan<Ciphertext> bs) const {
    return Sub(bs, as);
  }
  std::vector<Plaintext> Sub(ConstSpan<Plaintext> as, ConstSpan<Plaintext> bs) const {
    std::vector<Plaintext> outs;
    for (int i=0; i<as.size(); i++) {
      outs.emplace_back(*as[i] - *bs[i]);
    }
    return outs;
  }

  void SubInplace(Span<Ciphertext> as, ConstSpan<Ciphertext> bs) const;
  void SubInplace(Span<Ciphertext> as, ConstSpan<Plaintext> bs) const;
  void SubInplace(Span<Plaintext> as, ConstSpan<Plaintext> bs) const {
    for (int i=0; i<as.size(); i++) {
      (*as[i]) -= (*bs[i]);
    }
  }

  std::vector<Ciphertext> Mul(ConstSpan<Ciphertext> as, ConstSpan<Plaintext> bs) const;
  std::vector<Ciphertext> Mul(ConstSpan<Plaintext> as, ConstSpan<Ciphertext> bs) const {
    return Mul(bs, as);
  }
  std::vector<Plaintext> Mul(ConstSpan<Plaintext> as, ConstSpan<Plaintext> bs) const {
    std::vector<Plaintext> outs;
    for (int i=0; i<as.size(); i++) {
      outs.emplace_back((*as[i]) * (*bs[i]));
    }
    return outs;
  }

  void MulInplace(Span<Ciphertext> as, ConstSpan<Plaintext> bs) const;
  void MulInplace(Span<Plaintext> as, ConstSpan<Plaintext> bs) const {
    for (int i=0; i<as.size(); i++) {
      (*as[i]) *= (*bs[i]);
    }
  };

  std::vector<Ciphertext> Negate(ConstSpan<Ciphertext> a) const;
  void NegateInplace(Span<Ciphertext> a) const;

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
