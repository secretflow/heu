// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "heu/library/algorithms/paillier_ipcl/ciphertext.h"

#include <string_view>

#include "cereal/archives/portable_binary.hpp"

#include "heu/library/algorithms/paillier_ipcl/utils.h"

namespace heu::lib::algorithms::paillier_ipcl {

std::string Ciphertext::ToString() const {
  return paillier_ipcl::ToString(bn_);
}

std::ostream &operator<<(std::ostream &os, const Ciphertext &c) {
  os << c.ToString();
  return os;
}

bool Ciphertext::operator==(const Ciphertext &other) const {
  return bn_ == other.bn_;
}

bool Ciphertext::operator!=(const Ciphertext &other) const {
  return bn_ != other.bn_;
}

yacl::Buffer Ciphertext::Serialize() const {
  std::ostringstream os;
  {
    cereal::PortableBinaryOutputArchive archive(os);
    archive(bn_);
  }
  yacl::Buffer buf(os.str().data(), os.str().size());
  return buf;
}

void Ciphertext::Deserialize(yacl::ByteContainerView in) {
  std::istringstream is((std::string)in);
  {
    cereal::PortableBinaryInputArchive archive(is);
    archive(bn_);
  }
}

}  // namespace heu::lib::algorithms::paillier_ipcl
