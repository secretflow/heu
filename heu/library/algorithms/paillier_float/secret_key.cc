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

#include "heu/library/algorithms/paillier_float/secret_key.h"

namespace heu::lib::algorithms::paillier_f {

SecretKey::SecretKey(PublicKey pk, BigInt p, BigInt q) : pk_(std::move(pk)) {
  lambda_ = (p - 1).Lcm(q - 1);  // lambda_ = lcm(p-1, q-1)

  x_ = pk_.g_.PowMod(lambda_, pk_.n_square_);
  x_ = (x_ - 1) / pk_.n_;
  x_ = x_.InvMod(pk_.n_);
}

std::string SecretKey::ToString() const {
  return fmt::format("F-paillier SK: lambda={}[{}bits], x={}[{}bits]",
                     lambda_.ToHexString(), lambda_.BitCount(),
                     x_.ToHexString(), x_.BitCount());
}

}  // namespace heu::lib::algorithms::paillier_f
