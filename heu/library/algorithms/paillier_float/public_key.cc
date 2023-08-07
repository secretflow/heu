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

#include "heu/library/algorithms/paillier_float/public_key.h"

#include <utility>

namespace heu::lib::algorithms::paillier_f {

PublicKey::PublicKey(const MPInt& n) : n_(n) { Init(); }

PublicKey::PublicKey(MPInt&& n) : n_(std::move(n)) { Init(); }

void PublicKey::Init() {
  g_ = n_ + MPInt::_1_;
  MPInt::Mul(n_, n_, &n_square_);  // n_square_ = n_ ** 2
  MPInt::Div3(n_, &max_int_);
}

std::string PublicKey::ToString() const {
  return fmt::format("F-paillier PK: n={}[{}bits], max_plaintext={}[~{}bits]",
                     n_.ToHexString(), n_.BitCount(),
                     PlaintextBound().ToHexString(),
                     PlaintextBound().BitCount());
}

}  // namespace heu::lib::algorithms::paillier_f
