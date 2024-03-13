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

#include "heu/library/phe/base/predefined_functions.h"

namespace heu::lib::phe {

// EncryptZero //

DEFINE_INVOKE_METHOD_RET_0(Ciphertext, EncryptZero)

Ciphertext Encryptor::EncryptZero() const {
  return std::visit([](const auto &clazz) { return DoCallEncryptZero(clazz); },
                    encryptor_ptr_);
}

// Encrypt //

DEFINE_INVOKE_METHOD_RET_1(Ciphertext, Encrypt)

Ciphertext Encryptor::Encrypt(const Plaintext &m) const {
  return std::visit(
      HE_DISPATCH(DO_INVOKE_METHOD_RET_1, Encryptor, Encrypt, Plaintext, m),
      encryptor_ptr_);
}

// EncryptWithAudit //

template <typename CLAZZ, typename PT>
using kHasScalarEncryptWithAudit =
    decltype(std::declval<const CLAZZ &>().EncryptWithAudit(PT()));

template <typename CLAZZ, typename PT>
auto DoCallEncryptWithAudit(const CLAZZ &sub_clazz, const PT &in1)
    -> std::enable_if_t<
        std::experimental::is_detected_v<kHasScalarEncryptWithAudit, CLAZZ, PT>,
        std::pair<Ciphertext, std::string>> {
  auto ca = sub_clazz.EncryptWithAudit(in1);
  return {Ciphertext(std::move(ca.first)), std::move(ca.second)};
}

template <typename CLAZZ, typename PT>
auto DoCallEncryptWithAudit(const CLAZZ &sub_clazz, const PT &in1)
    -> std::enable_if_t<!std::experimental::is_detected_v<
                            kHasScalarEncryptWithAudit, CLAZZ, PT>,
                        std::pair<Ciphertext, std::string>> {
  auto ca = sub_clazz.EncryptWithAudit(absl::MakeConstSpan<>({&in1}));
  return {Ciphertext(std::move(ca.first[0])), std::move(ca.second[0])};
}

std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const Plaintext &m) const {
  return std::visit(HE_DISPATCH(DO_INVOKE_METHOD_RET_1, Encryptor,
                                EncryptWithAudit, Plaintext, m),
                    encryptor_ptr_);
}

SchemaType Encryptor::GetSchemaType() const { return schema_type_; }

}  // namespace heu::lib::phe
