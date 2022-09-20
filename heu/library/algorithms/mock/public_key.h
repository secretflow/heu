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

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::mock {

class PublicKey : public HeObject<PublicKey> {
 public:
  size_t key_size_ = 0;
  MPInt max_int_;

  // for msgpack
  MSGPACK_DEFINE(key_size_, max_int_);

  bool operator==(const PublicKey &other) const {
    return key_size_ == other.key_size_ && max_int_ == other.max_int_;
  }

  bool operator!=(const PublicKey &other) const {
    return !this->operator==(other);
  }

  [[nodiscard]] std::string ToString() const override {
    return fmt::format("Mock phe public key with {} bit length", key_size_);
  }

  // Valid plaintext range: (max_int_, -max_int_)
  [[nodiscard]] const MPInt &PlaintextBound() const & { return max_int_; }
};

}  // namespace heu::lib::algorithms::mock
