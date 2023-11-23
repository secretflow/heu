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

#include <string>

#include "heu/library/algorithms/mock/plaintext.h"
#include "heu/library/algorithms/util/he_object.h"

namespace heu::lib::algorithms::mock {

class PublicKey : public HeObject<PublicKey> {
 public:
  // [SPI: Important]
  bool operator==(const PublicKey &other) const {
    return key_size_ == other.key_size_ && max_int_ == other.max_int_;
  }

  // [SPI: Important]
  bool operator!=(const PublicKey &other) const {
    return !this->operator==(other);
  }

  // [SPI: Critical]
  [[nodiscard]] std::string ToString() const override {
    return fmt::format("Mock phe public key with {} bit length", key_size_);
  }

  // Valid plaintext range: [max_int_, -max_int_]
  // [SPI: Critical]
  [[nodiscard]] const Plaintext &PlaintextBound() const & { return max_int_; }

  // If you don't inherit from HeObject, please implement the following
  // functions.
  // Functions inherited from HeObject:
  // yacl::Buffer Serialize() const;                // [SPI: Critical]
  // void Deserialize(yacl::ByteContainerView in);  // [SPI: Critical]

  // for msgpack
  MSGPACK_DEFINE(key_size_, max_int_);
  size_t key_size_ = 0;
  Plaintext max_int_;
};

}  // namespace heu::lib::algorithms::mock
