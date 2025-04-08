// Copyright (C) 2021 Intel Corporation
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

#include <ostream>
#include <string>

#include "ipcl/bignum.h"
#include "ipcl/ciphertext.hpp"
#include "yacl/base/byte_container_view.h"

namespace heu::lib::algorithms::paillier_ipcl {

// SPI: Do not change class name.
class Ciphertext {
 public:
  Ciphertext() = default;
  explicit Ciphertext(BigNumber &bn) : bn_(bn) {};

  std::string ToString() const;
  friend std::ostream &operator<<(std::ostream &os, const Ciphertext &c);

  bool operator==(const Ciphertext &other) const;
  bool operator!=(const Ciphertext &other) const;

  yacl::Buffer Serialize() const;
  void Deserialize(yacl::ByteContainerView in);

  operator BigNumber() { return bn_; }

  BigNumber bn_;
};

}  // namespace heu::lib::algorithms::paillier_ipcl
