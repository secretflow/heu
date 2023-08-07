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

#include <utility>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/base/ecc/ecc_spi.h"

#include "heu/library/algorithms/elgamal/utils/lookup_table.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::elgamal {

using yacl::crypto::EcGroup;
using yacl::crypto::EcPoint;

class SecretKey {
 public:
  SecretKey() {}

  SecretKey(const MPInt &x, const std::shared_ptr<EcGroup> &curve)
      : x_(x), curve_(curve) {
    table_ = std::make_shared<LookupTable>();
    table_->Init(curve_);
  }

  const MPInt &GetX() const { return x_; }

  bool operator==(const SecretKey &other) const;
  bool operator!=(const SecretKey &other) const;

  std::string ToString() const;

  yacl::Buffer Serialize() const;
  void Deserialize(yacl::ByteContainerView in);

  const std::shared_ptr<LookupTable> &GetInitedLookupTable() const {
    return table_;
  }

 private:
  MPInt x_;
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  std::shared_ptr<LookupTable> table_;
};

}  // namespace heu::lib::algorithms::elgamal
