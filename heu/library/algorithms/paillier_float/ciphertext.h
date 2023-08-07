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

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::paillier_f {

// todo: define custom Plaintext class.
//  paillier_float's plaintext is not MPInt, it can be a float
using Plaintext = MPInt;

// Forward declaration
class PublicKey;
class Evaluator;
class Decryptor;

class Ciphertext : public HeObject<Ciphertext> {
  friend class SecretKey;
  friend class Evaluator;
  friend class Decryptor;

 public:
  Ciphertext() = default;

  explicit Ciphertext(MPInt&& c, int exponent = 0)
      : c_(std::move(c)), exponent_(exponent) {}

  bool operator==(const Ciphertext& other) const { return c_ == other.c_; }

  bool operator!=(const Ciphertext& other) const {
    return !this->operator==(other);
  }

  [[nodiscard]] std::string ToString() const override {
    return fmt::format("{}+{}", c_.ToString(), exponent_);
  }

 private:
  MPInt c_;
  int exponent_ = 0;

 public:
  MSGPACK_DEFINE(c_, exponent_);
};

}  // namespace heu::lib::algorithms::paillier_f
