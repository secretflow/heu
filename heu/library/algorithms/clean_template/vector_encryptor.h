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

#include "heu/library/algorithms/clean_template/ciphertext.h"
#include "heu/library/algorithms/clean_template/plaintext.h"
#include "heu/library/algorithms/clean_template/public_key.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::your_algo {

class Encryptor {
 public:
  explicit Encryptor(const PublicKey &pk);

  std::vector<Ciphertext> EncryptZero(int64_t size) const;
  std::vector<Ciphertext> Encrypt(ConstSpan<Plaintext> pts) const;

  std::pair<std::vector<Ciphertext>, std::vector<std::string>> EncryptWithAudit(
      ConstSpan<Plaintext> pts) const;
};

}  // namespace heu::lib::algorithms::your_algo
