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

class SecretKey : public HeObject<SecretKey> {
 public:
  size_t key_size_ = 0;

  // for msgpack
  MSGPACK_DEFINE(key_size_);

  bool operator==(const SecretKey &other) const {
    return key_size_ == other.key_size_;
  }

  bool operator!=(const SecretKey &other) const {
    return !this->operator==(other);
  }

  [[nodiscard]] std::string ToString() const override {
    return fmt::format("Mock phe secret key with {} bit length", key_size_);
  }
};

}  // namespace heu::lib::algorithms::mock
