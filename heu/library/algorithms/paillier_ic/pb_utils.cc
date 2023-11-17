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

#include "heu/library/algorithms/paillier_ic/pb_utils.h"

namespace heu::lib::algorithms::paillier_ic {
pb_ns::Bigint MPInt2Bigint(const MPInt &mpint) {
  pb_ns::Bigint bi;
  bi.set_is_neg(mpint.IsNegative());
  auto buf_len = mpint.ToMagBytes(nullptr, 0);
  bi.mutable_little_endian_value()->resize(buf_len);
  mpint.ToMagBytes(reinterpret_cast<unsigned char *>(
                       bi.mutable_little_endian_value()->data()),
                   buf_len, yacl::Endian::little);
  return bi;
}

MPInt Bigint2MPint(const pb_ns::Bigint &bi) {
  MPInt mp;
  mp.FromMagBytes(bi.little_endian_value(), yacl::Endian::little);
  if (bi.is_neg()) {
    mp.NegateInplace();
  }
  return mp;
}

}  // namespace heu::lib::algorithms::paillier_ic
