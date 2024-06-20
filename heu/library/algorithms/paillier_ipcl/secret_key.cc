// Copyright (C) 2021 Intel Corporation
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

#include "heu/library/algorithms/paillier_ipcl/secret_key.h"

namespace {
bool IsEqual(const std::shared_ptr<BigNumber> &a,
             const std::shared_ptr<BigNumber> &b) {
  return a && b && *a == *b;
}
}  // namespace

namespace heu::lib::algorithms::paillier_ipcl {
bool SecretKey::operator==(const SecretKey &other) const {
  return IsEqual(ipcl_prikey_.getP(), other.ipcl_prikey_.getP()) &&
         IsEqual(ipcl_prikey_.getQ(), other.ipcl_prikey_.getQ()) &&
         ipcl_prikey_.getLambda() == other.ipcl_prikey_.getLambda();
}

bool SecretKey::operator!=(const SecretKey &other) const {
  return !(*this == other);
}

std::string SecretKey::ToString() const {
  std::string p;
  ipcl_prikey_.getP()->num2hex(p);
  std::string q;
  ipcl_prikey_.getP()->num2hex(q);
  return fmt::format("IPCL SK: p={}[{}bits], q={}[{}bits]", p,
                     ipcl_prikey_.getP()->BitSize(), q,
                     ipcl_prikey_.getQ()->BitSize());
}

yacl::Buffer SecretKey::Serialize() const {
  std::ostringstream os;
  {
    cereal::PortableBinaryOutputArchive archive(os);
    archive(ipcl_prikey_);
  }
  yacl::Buffer buf(os.str().data(), os.str().size());
  return buf;
}

void SecretKey::Deserialize(yacl::ByteContainerView in) {
  std::istringstream is((std::string)in);
  {
    cereal::PortableBinaryInputArchive archive(is);
    archive(ipcl_prikey_);
  }
}

}  // namespace heu::lib::algorithms::paillier_ipcl
