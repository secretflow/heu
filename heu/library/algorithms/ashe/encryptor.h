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

#include "heu/library/algorithms/ashe/ciphertext.h"
#include "heu/library/algorithms/ashe/public_parameters.h"
#include "heu/library/algorithms/ashe/secret_key.h"

namespace heu::lib::algorithms::ashe {
class Encryptor {
 public:
  explicit Encryptor(PublicParameters pk, SecretKey sk)
      : pp_(std::move(pk)), sk_(std::move(sk)) {}

  [[nodiscard]] Ciphertext EncryptZero() const;
  [[nodiscard]] Ciphertext Encrypt(const Plaintext &m) const;

  void Encrypt(const Plaintext &m, Ciphertext *out) const;

  [[nodiscard]] std::pair<Ciphertext, std::string> EncryptWithAudit(
      const Plaintext &m) const;

 private:
  template <bool audit = false>
  Ciphertext EncryptImpl(const Plaintext &m, std::string *audit_str) const;
  PublicParameters pp_;
  SecretKey sk_;
  BigInt ZERO = BigInt(0);
  BigInt MAX = BigInt(UINT64_MAX);
};
}  // namespace heu::lib::algorithms::ashe
