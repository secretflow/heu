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

#include "heu/library/phe/encryptor.h"

namespace heu::lib::phe {

Ciphertext Encryptor::EncryptZero() const {
  return std::visit(
      [](const auto& clazz) { return Ciphertext(clazz.EncryptZero()); },
      encryptor_ptr_);
}

Ciphertext Encryptor::Encrypt(const Plaintext& m) const {
  return std::visit(
      [&](const auto& clazz) { return Ciphertext(clazz.Encrypt(m)); },
      encryptor_ptr_);
}

std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const Plaintext& m) const {
  return std::visit(
      [&](const auto& clazz) -> std::pair<Ciphertext, std::string> {
        auto ca = clazz.EncryptWithAudit(m);
        return {Ciphertext(std::move(ca.first)), std::move(ca.second)};
      },
      encryptor_ptr_);
}

}  // namespace heu::lib::phe
