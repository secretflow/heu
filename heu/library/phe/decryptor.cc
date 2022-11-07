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

#include "heu/library/phe/decryptor.h"

namespace heu::lib::phe {

void Decryptor::Decrypt(const Ciphertext& ct, Plaintext* out) const {
#define FUNC(ns)                                                             \
  [&](const ns::Decryptor& decryptor) {                                      \
    if (!out->IsHoldType<ns::Plaintext>()) {                                 \
      ns::Plaintext inner_pt;                                                \
      decryptor.Decrypt(ct.As<ns::Ciphertext>(), &inner_pt);                 \
      *out = std::move(inner_pt);                                            \
    } else {                                                                 \
      decryptor.Decrypt(ct.As<ns::Ciphertext>(), &out->As<ns::Plaintext>()); \
    }                                                                        \
  }

  std::visit(HE_DISPATCH(FUNC), decryptor_ptr_);
#undef FUNC
}

Plaintext Decryptor::Decrypt(const Ciphertext& ct) const {
  return std::visit(HE_DISPATCH(HE_METHOD_RET_1, Decryptor, Plaintext, Decrypt,
                                Ciphertext, ct),
                    decryptor_ptr_);
}

SchemaType Decryptor::GetSchemaType() const { return schema_type_; }

}  // namespace heu::lib::phe
