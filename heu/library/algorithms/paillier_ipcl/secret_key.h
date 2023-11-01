// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ipcl/pri_key.hpp"
#include "yacl/base/byte_container_view.h"

namespace heu::lib::algorithms::paillier_ipcl {

class SecretKey {
 public:
  void Init(ipcl::PrivateKey sk) { ipcl_prikey_ = sk; }

  bool operator==(const SecretKey &other) const;
  bool operator!=(const SecretKey &other) const;

  std::string ToString() const;

  yacl::Buffer Serialize() const { YACL_THROW("Not implemented."); }

  void Deserialize(yacl::ByteContainerView) { YACL_THROW("Not implemented."); }

  ipcl::PrivateKey ipcl_prikey_;
};

}  // namespace heu::lib::algorithms::paillier_ipcl
