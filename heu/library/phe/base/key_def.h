// Copyright 2023 Ant Group Co., Ltd.
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

#include "heu/library/phe/base/plaintext.h"
#include "heu/library/phe/base/serializable_types.h"

namespace heu::lib::phe {

using SecretKey = SerializableVariant<HE_NAMESPACE_LIST(SecretKey)>;

class PublicKey : public SerializableVariant<HE_NAMESPACE_LIST(PublicKey)> {
 public:
  using SerializableVariant<HE_NAMESPACE_LIST(PublicKey)>::SerializableVariant;
  using SerializableVariant<HE_NAMESPACE_LIST(PublicKey)>::operator=;

  // Valid plaintext range: (PlaintextBound(), -PlaintextBound())
  [[nodiscard]] Plaintext PlaintextBound() const & {
    return this->Visit([](const auto &clazz) -> Plaintext {
      FOR_EACH_TYPE(clazz) return Plaintext(clazz.PlaintextBound());
    });
  }
};

}  // namespace heu::lib::phe
