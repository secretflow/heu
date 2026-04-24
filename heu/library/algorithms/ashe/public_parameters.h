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

#include "heu/library/algorithms/util/big_int.h"
#include "heu/library/algorithms/util/he_object.h"

namespace heu::lib::algorithms::ashe {
class PublicParameters : public HeObject<PublicParameters> {
 private:
  BigInt plaintextBound;

  static std::string ToHexString(const std::vector<BigInt> &vec) {
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < vec.size(); ++i) {
      if (i != 0) {
        oss << ", ";
      }
      oss << "0x" << vec[i].ToHexString();
    }
    oss << "]";
    return oss.str();
  }

 public:
  int64_t k_r1 = 4384;
  int64_t k_p = 1536;
  int64_t k_q = 1008;
  int64_t k_r2 = 512;
  int64_t k_m = 64;
  std::vector<BigInt> randomZeros;
  BigInt M[2];

  PublicParameters() = default;

  PublicParameters(int64_t k_r1, int64_t k_p, int64_t k_q, int64_t k_r2,
                   int64_t k_m);

  PublicParameters(int64_t k_r1, int64_t k_p, int64_t k_q, int64_t k_r2,
                   int64_t k_m, const std::vector<BigInt> &zeros);

  bool operator==(const PublicParameters &other) const {
    return k_r1 == other.k_r1 && k_p == other.k_p && k_q == other.k_q &&
           k_r2 == other.k_r2 && k_m == other.k_m;
  }

  bool operator!=(const PublicParameters &other) const {
    return !this->operator==(other);
  }

  [[nodiscard]] std::string ToString() const override;

  [[nodiscard]] const BigInt &PlaintextBound() const & { return M[1]; }

  void Init();

  [[nodiscard]] std::pair<BigInt, BigInt> MessageSpace() const {
    return std::make_pair(M[0], M[1]);
  }

  MSGPACK_DEFINE(k_r1, k_p, k_q, k_r2, k_m, M, randomZeros);
};
}  // namespace heu::lib::algorithms::ashe
