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

#pragma once
#include <string>
#include <utility>
#include <variant>

#include "heu/library/phe/schema.h"
#include "heu/library/phe/serializable_types.h"

namespace heu::lib::phe {

typedef std::variant<HE_NAMESPACE_LIST(Encryptor)> EncryptorType;

class Encryptor {
 public:
  explicit Encryptor(EncryptorType encryptor_ptr)
      : encryptor_ptr_(std::move(encryptor_ptr)) {}

  // Get Enc(0)
  Ciphertext EncryptZero() const;
  Ciphertext Encrypt(const Plaintext& clazz) const;
  std::pair<Ciphertext, std::string> EncryptWithAudit(
      const Plaintext& clazz) const;

 private:
  EncryptorType encryptor_ptr_;
};

}  // namespace heu::lib::phe
