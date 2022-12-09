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

#include <string_view>
#include "cereal/archives/portable_binary.hpp"
#include "heu/library/algorithms/paillier_ipcl/ciphertext.h"
#include "heu/library/algorithms/paillier_ipcl/utils.h"

namespace heu::lib::algorithms::paillier_ipcl {

std::string Ciphertext::ToString() const {
  return to_string(bn_);
}
  
std::ostream &operator<<(std::ostream &os, const Ciphertext &c) {
  os << c.ToString();
  return os;
}

bool Ciphertext::operator==(const Ciphertext &other) const {
  return bn_ == other.bn_;
}

bool Ciphertext::operator!=(const Ciphertext &other) const {
  return bn_ != other.bn_;
}

yacl::Buffer Ciphertext::Serialize() const {
  std::ostringstream os;
  {
    cereal::PortableBinaryOutputArchive archive(os);
    archive(bn_);
  }
  yacl::Buffer buf(os.str().data(), os.str().size());
  return buf;
}

void Ciphertext::Deserialize(yacl::ByteContainerView in) {
  std::istringstream is((std::string)in);
  {
    cereal::PortableBinaryInputArchive archive(is);
    archive(bn_);
  }
}

}  // namespace heu::lib::algorithms::paillier_ipcl
