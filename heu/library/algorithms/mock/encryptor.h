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

#include <utility>

#include "heu/library/algorithms/mock/ciphertext.h"
#include "heu/library/algorithms/mock/plaintext.h"
#include "heu/library/algorithms/mock/public_key.h"

namespace heu::lib::algorithms::mock {

class Encryptor {
 public:
  explicit Encryptor(PublicKey pk) : pk_(std::move(pk)) {}

  [[nodiscard]] Ciphertext EncryptZero() const;

  [[nodiscard]] Ciphertext Encrypt(const Plaintext& m) const;

  [[nodiscard]] std::pair<Ciphertext, std::string> EncryptWithAudit(
      const Plaintext& m) const;

  [[nodiscard]] const PublicKey& public_key() const { return pk_; }

 private:
  PublicKey pk_;
};

}  // namespace heu::lib::algorithms::mock
