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
#include "heu/library/algorithms/mock/switch_spi.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::mock {

class Encryptor {
 public:
  // [SPI: Critical]
  explicit Encryptor(const PublicKey& pk) : pk_(pk) {}

// To algorithm developers:
// The Encryptor class supports two different interfaces:
// IMPL_SCALAR_SPI and IMPL_VECTORIZED_SPI. You only need to choose either SPI
// to implementation, you can completely remove the other SPI, including
// function declaration and function implementation.
// Please see switch_spi.h for details.
#ifdef IMPL_SCALAR_SPI
  // [SPI: Critical]
  [[nodiscard]] Ciphertext EncryptZero() const;

  // [SPI: Critical]
  [[nodiscard]] Ciphertext Encrypt(const Plaintext& m) const;

  // [SPI: Important]
  // Input: plaintext
  // Output: pair of <ciphertext, audit_string>
  [[nodiscard]] std::pair<Ciphertext, std::string> EncryptWithAudit(
      const Plaintext& m) const;
#endif

#ifdef IMPL_VECTORIZED_SPI
  // [SPI: Critical]
  [[nodiscard]] std::vector<Ciphertext> EncryptZero(int64_t size) const;

  // [SPI: Critical]
  std::vector<Ciphertext> Encrypt(ConstSpan<Plaintext> pts) const;

  // [SPI: Important]
  // Input: plaintext
  // Output: pair of <ciphertext list, audit_string list>
  std::pair<std::vector<Ciphertext>, std::vector<std::string>> EncryptWithAudit(
      ConstSpan<Plaintext> pts) const;
#endif

 private:
  PublicKey pk_;
};

}  // namespace heu::lib::algorithms::mock
