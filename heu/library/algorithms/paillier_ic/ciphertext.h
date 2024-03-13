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

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::paillier_ic {

using Plaintext = MPInt;

class Ciphertext {
 public:
  Ciphertext() = default;

  explicit Ciphertext(MPInt c) : c_(std::move(c)) {}

  [[nodiscard]] std::string ToString() const { return c_.ToString(); }

  bool operator==(const Ciphertext &other) const { return c_ == other.c_; }

  bool operator!=(const Ciphertext &other) const {
    return !this->operator==(other);
  }

  [[nodiscard]] yacl::Buffer Serialize() const;

  void Deserialize(yacl::ByteContainerView in);

  // TODO: make this private.
  MPInt c_;
};

}  // namespace heu::lib::algorithms::paillier_ic
