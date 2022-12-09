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

#include "ipcl/pri_key.hpp"
#include "yacl/base/byte_container_view.h"

namespace heu::lib::algorithms::paillier_ipcl {

class SecretKey {
public:
  void Init(ipcl::PrivateKey sk) {
    ipcl_prikey_ = sk;
  }

  bool operator==(const SecretKey &other) const;
  bool operator!=(const SecretKey &other) const;

  std::string ToString() const;

  yacl::Buffer Serialize() const {
    throw std::runtime_error("Not implemented.");
  }
  void Deserialize(yacl::ByteContainerView in) {
    throw std::runtime_error("Not implemented.");
  }

  ipcl::PrivateKey ipcl_prikey_;
};

}  // namespace heu::lib::algorithms::paillier_ipcl
