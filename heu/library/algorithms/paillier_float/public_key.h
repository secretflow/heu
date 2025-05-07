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

#include "heu/library/algorithms/util/big_int.h"
#include "heu/library/algorithms/util/he_object.h"

namespace heu::lib::algorithms::paillier_f {

namespace internal {
// Forward declaration
class Codec;
}  // namespace internal

// Forward declaration
class KeyGenerator;
class Evaluator;
class Encryptor;
class Decryptor;
class SecretKey;

class PublicKey : public HeObject<PublicKey> {
 public:
  PublicKey() = default;

  // Valid plaintext range: [max_int_, -max_int_]
  [[nodiscard]] const BigInt &PlaintextBound() const & { return max_int_; }

  [[nodiscard]] std::string ToString() const override;

  bool operator==(const PublicKey &other) const {
    return n_ == other.n_ && g_ == other.g_;
  }

  bool operator!=(const PublicKey &other) const {
    return !this->operator==(other);
  }

  // TODO: other variable members could be calculated based on n_
  // n_ is the only thing should be serialized
  MSGPACK_DEFINE(n_, n_square_, g_, max_int_);

 private:
  explicit PublicKey(const BigInt &n);
  explicit PublicKey(BigInt &&n);

  // setup bits_, n_square_, g_, max_int_ based on n_
  void Init();

  friend class KeyGenerator;
  friend class SecretKey;
  friend class Encryptor;
  friend class Decryptor;
  friend class Evaluator;
  friend class internal::Codec;

  BigInt n_;         // public modulus n = p * q
  BigInt n_square_;  // n_ * n_
  BigInt g_;         // n_ + 1

  // Maximum int that may safely be stored. This can be increased, if you are
  // happy to redefine "safely" and lower the chance of detecting an integer
  // overflow.
  // Bound: [max_int_, -max_int_]
  BigInt max_int_;  // n_ / 3
};

}  // namespace heu::lib::algorithms::paillier_f
