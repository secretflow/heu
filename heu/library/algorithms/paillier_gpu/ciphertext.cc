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

#include "heu/library/algorithms/paillier_gpu/ciphertext.h"

#include <string>

namespace heu::lib::algorithms::paillier_g {

std::string Ciphertext::ToString() const {
  MPInt pt;
  pt.FromMagBytes(yacl::ByteContainerView((uint8_t*)(ct_.c), 512),
                  algorithms::Endian::little);
  return pt.ToString();
}

std::string Ciphertext::ToHexString() const {
  MPInt pt;
  pt.FromMagBytes(yacl::ByteContainerView((uint8_t*)(ct_.c), 512),
                  algorithms::Endian::little);
  return pt.ToHexString();
}

bool Ciphertext::operator==(const Ciphertext& other) const {
  return std::equal(ct_.c, ct_.c + 512, other.ct_.c);
}

bool Ciphertext::operator!=(const Ciphertext& other) const {
  return !this->operator==(other);
}

}  // namespace heu::lib::algorithms::paillier_g
