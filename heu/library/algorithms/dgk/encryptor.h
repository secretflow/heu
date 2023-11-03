// Copyright 2023 zhangwfjh
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

#include "heu/library/algorithms/dgk/ciphertext.h"
#include "heu/library/algorithms/dgk/public_key.h"
#include "heu/library/algorithms/dgk/secret_key.h"

namespace heu::lib::algorithms::dgk {

class Encryptor {
 public:
  explicit Encryptor(const PublicKey& pk) : pk_{std::move(pk)} {}

  Ciphertext EncryptZero() const;
  Ciphertext Encrypt(const Plaintext& m) const;

  std::pair<Ciphertext, std::string> EncryptWithAudit(const Plaintext& m) const;

 private:
  const PublicKey pk_;
};

}  // namespace heu::lib::algorithms::dgk
