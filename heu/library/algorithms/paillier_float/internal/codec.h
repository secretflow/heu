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

#include "absl/types/optional.h"

#include "heu/library/algorithms/paillier_float/public_key.h"
#include "heu/library/algorithms/util/big_int.h"

namespace heu::lib::algorithms::paillier_f::internal {

struct EncodedNumber {
  BigInt encoding;
  int exponent;

  EncodedNumber() : exponent(0) {}
};

class Codec {
 public:
  static const int kBase = 16;
  static const int kLog2Base = 4;
  static const int kDoubleMantissaBits = 53;
  static const BigInt kBaseCache;  // cache kBase in MPInt type

 public:
  explicit Codec(PublicKey pk) : pk_(std::move(pk)) {}

  EncodedNumber Encode(const BigInt &scalar, int exponent = 0) const;

  EncodedNumber Encode(double scalar,
                       absl::optional<float> precision = absl::nullopt,
                       absl::optional<int> max_exponent = absl::nullopt) const;

  void Decode(const EncodedNumber &in, double *out) const;

  void Decode(const EncodedNumber &in, BigInt *out) const;

 private:
  BigInt GetMantissa(const EncodedNumber &encoded) const;

 private:
  PublicKey pk_;
};

}  // namespace heu::lib::algorithms::paillier_f::internal
