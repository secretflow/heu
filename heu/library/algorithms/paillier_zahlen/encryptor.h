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

#include <mutex>
#include <utility>

#include "heu/library/algorithms/paillier_zahlen/ciphertext.h"
#include "heu/library/algorithms/paillier_zahlen/public_key.h"
#include "heu/library/algorithms/paillier_zahlen/secret_key.h"

namespace heu::lib::algorithms::paillier_z {

class Encryptor {
 public:
  explicit Encryptor(PublicKey pk);
  Encryptor(const Encryptor &from);

  Ciphertext EncryptZero() const;  // Get Enc(0)
  Ciphertext Encrypt(const BigInt &m) const;
  std::pair<Ciphertext, std::string> EncryptWithAudit(const BigInt &m) const;

  const PublicKey &public_key() const { return pk_; }

  // Get R^n
  BigInt GetRn() const;

 private:
  template <bool audit = false>
  Ciphertext EncryptImpl(const BigInt &m,
                         std::string *audit_str = nullptr) const;

 private:
  const PublicKey pk_;
};

}  // namespace heu::lib::algorithms::paillier_z
