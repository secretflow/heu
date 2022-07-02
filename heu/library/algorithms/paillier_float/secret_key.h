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

#include <memory>

#include "msgpack.hpp"

#include "heu/library/algorithms/paillier_float/public_key.h"
#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::paillier_f {
// Forward declaration
class Decryptor;

class SecretKey : public HeObject<SecretKey> {
 public:
  SecretKey() = default;
  SecretKey(PublicKey pk, MPInt p, MPInt q);

 private:
  MPInt x_;
  MPInt lambda_;
  PublicKey pk_;

 public:
  MSGPACK_DEFINE(x_, lambda_, pk_);
  [[nodiscard]] std::string ToString() const override;

  friend class KeyGenerator;
  friend class Decryptor;
};

}  // namespace heu::lib::algorithms::paillier_f
