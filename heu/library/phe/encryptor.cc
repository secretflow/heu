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
  return std::visit(HE_DISPATCH(HE_METHOD_RET_1, Encryptor, Ciphertext, Encrypt,
                                Plaintext, m),
                    encryptor_ptr_);
}

std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const Plaintext& m) const {
#define FUNC(ns)                                                         \
  [&](const ns::Encryptor& eval) -> std::pair<Ciphertext, std::string> { \
    auto ca = eval.EncryptWithAudit(m.As<ns::Plaintext>());              \
    return {Ciphertext(std::move(ca.first)), std::move(ca.second)};      \
  }

  return std::visit(HE_DISPATCH(FUNC), encryptor_ptr_);
#undef FUNC
}

SchemaType Encryptor::GetSchemaType() const { return schema_type_; }

}  // namespace heu::lib::phe
