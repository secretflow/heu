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
#include <utility>

#include "heu/algorithms/incubator/mock_phe/base.h"
#include "heu/spi/he/sketches/scalar/phe/encryptor.h"

namespace heu::algos::mock_phe {

class Encryptor : public spi::PheEncryptorScalarSketch<Plaintext, Ciphertext> {
 public:
  explicit Encryptor(const std::shared_ptr<PublicKey> &pk) : pk_(pk) {}

  [[nodiscard]] Ciphertext EncryptZeroT() const override;

  [[nodiscard]] Ciphertext Encrypt(const Plaintext &m) const override;
  void Encrypt(const Plaintext &plaintext, Ciphertext *out) const override;

  void EncryptWithAudit(const Plaintext &plaintext, Ciphertext *ct_out,
                        std::string *audit_out) const override;

 private:
  std::shared_ptr<PublicKey> pk_;
};

}  // namespace heu::algos::mock_phe
