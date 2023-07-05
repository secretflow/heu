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

#include <ostream>
#include <string>
#include <utility>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/base/ecc/ecc_spi.h"

#include "heu/library/algorithms/elgamal/public_key.h"

namespace heu::lib::algorithms::elgamal {

// SPI: Do not change class name.
struct Ciphertext {
  yacl::crypto::EcPoint c1;
  yacl::crypto::EcPoint c2;

  Ciphertext() = default;

  Ciphertext(std::shared_ptr<yacl::crypto::EcGroup> curve,
             const yacl::crypto::EcPoint &c_1, const yacl::crypto::EcPoint &c_2)
      : c1(c_1), c2(c_2), ec(std::move(curve)) {}

  std::string ToString() const;
  friend std::ostream &operator<<(std::ostream &os, const Ciphertext &c);

  bool operator==(const Ciphertext &other) const;
  bool operator!=(const Ciphertext &other) const;

  // Used for fast deserialize, not thread safe
  static void EnableEcGroup(
      const std::shared_ptr<yacl::crypto::EcGroup> &curve);

  yacl::Buffer Serialize(bool with_meta = false) const;
  void Deserialize(yacl::ByteContainerView in);

 private:
  // todo: ec should be removed
  std::shared_ptr<yacl::crypto::EcGroup> ec;
};

}  // namespace heu::lib::algorithms::elgamal
