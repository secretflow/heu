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

#include <string>

#include "heu/algorithms/incubator/ishe/base.h"
#include "heu/spi/he/sketches/scalar/phe/encryptor.h"

namespace heu::algos::ishe {

class Encryptor : public spi::PheEncryptorScalarSketch<Plaintext, Ciphertext> {
 public:
  explicit Encryptor(const std::shared_ptr<PublicKey> &pk,
                     const std::shared_ptr<SecretKey> &sk)
      : pk_(pk), sk_(sk) {
    InitOnes();
  }

  [[nodiscard]] Ciphertext EncryptZeroT() const override;

  [[nodiscard]] Ciphertext Encrypt(const Plaintext &m) const override;
  [[nodiscard]] Ciphertext Encrypt(const Plaintext &m, const MPInt &d) const;

  void Encrypt(const Plaintext &plaintext, Ciphertext *out) const override;

  void EncryptWithAudit(const Plaintext &plaintext, Ciphertext *ct_out,
                        std::string *audit_out) const override;

  void InitOnes() const {
    for (int i = 1; i <= 100; i++) {
      pk_->ADDONES.emplace_back(Encrypt(MPInt(1), MPInt(i)).n_);
    }
    for (int i = 1; i <= 50; i++) {
      pk_->ONES.emplace_back(Encrypt(MPInt(1), MPInt(1)).n_);
    }
    for (int i = 1; i <= 20; i++) {
      pk_->NEGS.emplace_back(Encrypt(MPInt(-1), MPInt(0)).n_);
    }
  }

 private:
  std::shared_ptr<PublicKey> pk_;
  std::shared_ptr<SecretKey> sk_;
};

}  // namespace heu::algos::ishe
