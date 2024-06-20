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

#include <mutex>
#include <utility>

#include "heu/library/algorithms/paillier_gpu/ciphertext.h"
#include "heu/library/algorithms/paillier_gpu/gpulib/gpupaillier.h"
#include "heu/library/algorithms/paillier_gpu/public_key.h"
#include "heu/library/algorithms/paillier_gpu/secret_key.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_g {

class Encryptor {
 public:
  explicit Encryptor(PublicKey pk);
  Encryptor(const Encryptor &from);

  const PublicKey &public_key() const { return pk_; }

  // Get R^n
  MPInt GetRn() const;

  // vector interface
  std::vector<Ciphertext> Encrypt(ConstSpan<Plaintext> pts) const;
  std::vector<Ciphertext> EncryptZero(int64_t size) const;
  std::pair<std::vector<Ciphertext>, std::vector<std::string>> EncryptWithAudit(
      ConstSpan<Plaintext> pts) const;

 private:
  template <bool audit = false>
  std::vector<Ciphertext> EncryptImpl(
      ConstSpan<Plaintext> pts,
      std::vector<std::string> *audit_strs = nullptr) const;

 private:
  const PublicKey pk_;
};

}  // namespace heu::lib::algorithms::paillier_g
