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

#include "heu/library/algorithms/util/big_int.h"
#include "heu/library/algorithms/util/he_object.h"

namespace heu::lib::algorithms::ashe {
using Plaintext = BigInt;

class Ciphertext : public HeObject<Ciphertext> {
 public:
  Ciphertext() = default;

  explicit Ciphertext(BigInt n) : n_(std::move(n)) {}

  [[nodiscard]] std::string ToString() const override {
    return fmt::format("CT: {}", n_);
  }

  bool operator==(const Ciphertext &other) const { return n_ == other.n_; }

  bool operator!=(const Ciphertext &other) const {
    return !this->operator==(other);
  }

  MSGPACK_DEFINE(n_);

  BigInt n_;
};
}  // namespace heu::lib::algorithms::ashe
