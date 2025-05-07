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

#include "heu/library/algorithms/paillier_gpu/gpulib/gpupaillier.h"
#include "heu/library/algorithms/util/big_int.h"
#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_g {

class Ciphertext : public HeObject<Ciphertext> {
 public:
  Ciphertext() = default;

  [[nodiscard]] std::string ToString() const;
  [[nodiscard]] std::string ToHexString() const;

  bool operator==(const Ciphertext &other) const;
  bool operator!=(const Ciphertext &other) const;

 public:
  h_paillier_ciphertext_t ct_;

  MSGPACK_DEFINE(ct_.c);
};

}  // namespace heu::lib::algorithms::paillier_g
