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

#include "yacl/crypto/base/ecc/ecc_spi.h"

#include "heu/library/algorithms/elgamal/utils/hash_map.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::elgamal {

using yacl::crypto::EcGroup;
using yacl::crypto::EcPoint;

class LookupTable {
 public:
  LookupTable() = default;

  void Init(const std::shared_ptr<EcGroup> &curve);

  int64_t Search(const EcPoint &p) const;  // Thread safe
  static const MPInt &MaxSupportedValue();

 private:
  // mG -> m
  std::shared_ptr<HashMap<EcPoint, int64_t>> table_;
  EcPoint table_max_pos_;
  EcPoint table_max_neg_;

  std::shared_ptr<EcGroup> curve_;
};

}  // namespace heu::lib::algorithms::elgamal
