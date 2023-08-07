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

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::mock {

// SPI: Do not change class name.
class Ciphertext : public HeObject<Ciphertext> {
 public:
  // [SPI: Critical]
  Ciphertext() = default;

  explicit Ciphertext(const MPInt &c) : bn_(c) {}

  // [SPI: Critical]
  [[nodiscard]] std::string ToString() const override { return bn_.ToString(); }

  // [SPI: Important]
  friend std::ostream &operator<<(std::ostream &os, const Ciphertext &c) {
    return os << c.ToString();
  }

  // [SPI: Important]
  bool operator==(const Ciphertext &other) const { return bn_ == other.bn_; }

  // [SPI: Important]
  bool operator!=(const Ciphertext &other) const {
    return !this->operator==(other);
  }

  // If you don't inherit from HeObject, please implement the following
  // functions.
  // Functions inherited from HeObject:
  // yacl::Buffer Serialize() const;                // [SPI: Critical]
  // void Deserialize(yacl::ByteContainerView in);  // [SPI: Critical]

  MSGPACK_DEFINE(bn_);
  MPInt bn_;  // It would be better if this field is private.
};

}  // namespace heu::lib::algorithms::mock
