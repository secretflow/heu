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

#include <utility>

#include "heu/library/algorithms/paillier_gpu/ciphertext.h"
#include "heu/library/algorithms/paillier_gpu/gpulib/gpupaillier.h"
#include "heu/library/algorithms/paillier_gpu/public_key.h"
#include "heu/library/algorithms/paillier_gpu/secret_key.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_g {

class Decryptor {
 public:
  explicit Decryptor(PublicKey pk, SecretKey sk)
      : pk_(std::move(pk)), sk_(std::move(sk)) {}

  std::vector<Plaintext> Decrypt(ConstSpan<Ciphertext> cts) const;
  void Decrypt(ConstSpan<Ciphertext> in_cts, Span<Plaintext> out_pts) const;

 private:
  PublicKey pk_;
  SecretKey sk_;
};

}  // namespace heu::lib::algorithms::paillier_g
