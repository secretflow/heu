// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

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
  explicit Ciphertext(BigNumber& bn) : bn_(bn) {};

  std::string ToString() const;
  friend std::ostream &operator<<(std::ostream &os, const Ciphertext &c);

  bool operator==(const Ciphertext &other) const;
  bool operator!=(const Ciphertext &other) const;

  yacl::Buffer Serialize() const;
  void Deserialize(yacl::ByteContainerView in);

  operator BigNumber() {
    return bn_;
  }
  BigNumber bn_;
};

}  // namespace heu::lib::algorithms::paillier_ipcl
