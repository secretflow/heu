// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

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
