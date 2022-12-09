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

#include "cereal/archives/portable_binary.hpp"
#include "heu/library/algorithms/paillier_ipcl/public_key.h"

namespace heu::lib::algorithms::paillier_ipcl {

bool PublicKey::operator==(const PublicKey &other) const {
  return ipcl_pubkey_.getN() == other.ipcl_pubkey_.getN()
         && ipcl_pubkey_.getG() == other.ipcl_pubkey_.getG()
         && ipcl_pubkey_.getHS() == other.ipcl_pubkey_.getHS();
}

bool PublicKey::operator!=(const PublicKey &other) const {
  return !this->operator==(other);
}

std::string PublicKey::ToString() const {
  std::string n;
  std::string hs;
  ipcl_pubkey_.getN()->num2hex(n);
  ipcl_pubkey_.getHS().num2hex(hs);
  return fmt::format(
    "IPCL public key: n={}[{}bits], h_s={}, max_plaintext={}[~{}bits]",
    n, ipcl_pubkey_.getN()->BitSize(), hs,
    PlaintextBound().ToHexString(), PlaintextBound().BitCount());
}

yacl::Buffer PublicKey::Serialize() const {
  std::ostringstream os;
  {
    cereal::PortableBinaryOutputArchive archive(os);
    archive(ipcl_pubkey_);
  }
  yacl::Buffer buf(os.str().data(), os.str().size());
  return buf;
}

void PublicKey::Deserialize(yacl::ByteContainerView in) {
  std::istringstream is((std::string)in);
  {
    cereal::PortableBinaryInputArchive archive(is);
    archive(ipcl_pubkey_);
  }
}

}  // namespace heu::lib::algorithms::paillier_ipcl
