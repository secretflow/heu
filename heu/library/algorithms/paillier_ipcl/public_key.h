// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "fmt/format.h"
#include "ipcl/pub_key.hpp"

#include "heu/library/algorithms/paillier_ipcl/plaintext.h"

namespace heu::lib::algorithms::paillier_ipcl {

class PublicKey {
 public:
  void Init(ipcl::PublicKey pk) {
    ipcl_pubkey_ = pk;
    pt_bound_.bn_ = *pk.getN() / 2;
  }

  bool operator==(const PublicKey &other) const;
  bool operator!=(const PublicKey &other) const;

  std::string ToString() const;

  // Valid plaintext range: (max_int_, -max_int_)
  inline const Plaintext &PlaintextBound() const & { return pt_bound_; }

  yacl::Buffer Serialize() const;
  void Deserialize(yacl::ByteContainerView in);

  ipcl::PublicKey ipcl_pubkey_;
  Plaintext pt_bound_;
};

}  // namespace heu::lib::algorithms::paillier_ipcl
