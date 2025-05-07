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

#include <string>

#include "fmt/format.h"

#include "heu/library/algorithms/util/big_int.h"
#include "heu/library/algorithms/util/he_object.h"

namespace heu::lib::algorithms::ou {

class SecretKey : public HeObject<SecretKey> {
 public:
  BigInt p_, q_;   // primes such that log2(p), log2(q) ~ n_bits / 3
  BigInt t_;       // a big prime factor of p - 1, i.e., p = t * u + 1.
  BigInt gp_inv_;  // L(g^{p-1} mod p^2))^{-1} mod p

  BigInt p2_;      // p^2
  BigInt p_half_;  // p/2
  BigInt n_;       // n = p^2 * q

  // for msgpack
  MSGPACK_DEFINE(p_, q_, t_, gp_inv_, p2_, p_half_, n_);

  bool operator==(const SecretKey &other) const {
    return p_ == other.p_ && q_ == other.q_ && t_ == other.t_ &&
           gp_inv_ == other.gp_inv_;
  }

  bool operator!=(const SecretKey &other) const {
    return !this->operator==(other);
  }

  [[nodiscard]] std::string ToString() const override {
    return fmt::format("OU SK, p={}[{}bits], q={}[{}bits]", p_.ToHexString(),
                       p_.BitCount(), q_.ToHexString(), q_.BitCount());
  }
};

}  // namespace heu::lib::algorithms::ou
