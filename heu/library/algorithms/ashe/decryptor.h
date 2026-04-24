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
class Decryptor {
 public:
  explicit Decryptor(PublicParameters pp, SecretKey sk)
      : pp_(std::move(pp)), sk_(std::move(sk)) {
    p = sk_.p_;
    q = sk_.q_;
  }

  void Decrypt(const Ciphertext &ct, Plaintext *out) const;

  [[nodiscard]] Plaintext Decrypt(const Ciphertext &ct) const;

 private:
  PublicParameters pp_;
  SecretKey sk_;
  BigInt half = BigInt(UINT64_MAX) / BigInt(2);
  BigInt MAX = BigInt(UINT64_MAX);
  BigInt p;
  BigInt q;
  BigInt ZERO = BigInt(0);
};
}  // namespace heu::lib::algorithms::ashe
