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

#include "heu/library/algorithms/ashe/public_parameters.h"

namespace heu::lib::algorithms::ashe {
PublicParameters::PublicParameters(int64_t k_r1, int64_t k_p, int64_t k_q,
                                   int64_t k_r2, int64_t k_m) {
  this->k_r1 = k_r1;
  this->k_p = k_p;
  this->k_q = k_q;
  this->k_r2 = k_r2;
  this->k_m = k_m;
  Init();
}

PublicParameters::PublicParameters(int64_t k_r1, int64_t k_p, int64_t k_q,
                                   int64_t k_r2, int64_t k_m,
                                   const std::vector<BigInt> &zeros)
    : PublicParameters(k_r1, k_p, k_q, k_r2, k_m) {
  this->randomZeros = zeros;
}

std::string PublicParameters::ToString() const {
  return fmt::format(
      "ashe PP: k_r1={}, k_p={}, k_q={}, "
      "k_r2={}, k_m={}, randomZeros={}[size:{}]",
      std::to_string(k_r1), std::to_string(k_p), std::to_string(k_q),
      std::to_string(k_r2), std::to_string(k_m), ToHexString(randomZeros),
      randomZeros.size());
}

void PublicParameters::Init() {
  this->M[1] = BigInt(2).Pow(k_m - 1) - BigInt(1);
  this->M[0] = -this->M[1];
}
}  // namespace heu::lib::algorithms::ashe
