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

#include "heu/library/algorithms/dj/ciphertext.h"
#include "heu/library/algorithms/dj/plaintext.h"
#include "heu/library/algorithms/dj/public_key.h"
#include "heu/library/algorithms/dj/secret_key.h"

namespace heu::lib::algorithms::dj {

class Decryptor {
 public:
  explicit Decryptor(const PublicKey& pk, const SecretKey& sk)
      : pk_{pk}, sk_{sk} {}

  void Decrypt(const Ciphertext& ct, Plaintext* out) const {
    *out = Decrypt(ct);
  }
  Plaintext Decrypt(const Ciphertext& ct) const;

 private:
  PublicKey const& pk_;
  SecretKey const& sk_;
};

}  // namespace heu::lib::algorithms::dj
