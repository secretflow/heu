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
#include "heu/library/algorithms/mock/secret_key.h"
#include "heu/library/algorithms/mock/switch_spi.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::mock {

class Decryptor {
 public:
  // [SPI: Critical]
  explicit Decryptor(const PublicKey& _, const SecretKey& sk) : sk_(sk) {}

// To algorithm developers:
// The Decryptor class supports two different interfaces:
// IMPL_SCALAR_SPI and IMPL_VECTORIZED_SPI. You only need to choose either SPI
// to implementation, you can completely remove the other SPI, including
// function declaration and function implementation.
// Please see switch_spi.h for details.
#ifdef IMPL_SCALAR_SPI
  // [SPI: Critical]
  void Decrypt(const Ciphertext& ct, Plaintext* out) const;
  // [SPI: Critical]
  [[nodiscard]] Plaintext Decrypt(const Ciphertext& ct) const;
#endif

#ifdef IMPL_VECTORIZED_SPI
  // [SPI: Critical]
  std::vector<Plaintext> Decrypt(ConstSpan<Ciphertext> cts) const;
  // [SPI: Critical]
  void Decrypt(ConstSpan<Ciphertext> in_cts, Span<Plaintext> out_pts) const;
#endif

 private:
  SecretKey sk_;
};

}  // namespace heu::lib::algorithms::mock
