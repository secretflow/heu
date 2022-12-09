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

#include "ipcl/pub_key.hpp"
#include "fmt/format.h"
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
  inline const Plaintext &PlaintextBound() const & {
    return pt_bound_;
  }

  yacl::Buffer Serialize() const;
  void Deserialize(yacl::ByteContainerView in);

  ipcl::PublicKey ipcl_pubkey_;
  Plaintext pt_bound_;
};

}  // namespace heu::lib::algorithms::paillier_ipcl
