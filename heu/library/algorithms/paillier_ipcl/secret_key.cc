// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "heu/library/algorithms/paillier_ipcl/secret_key.h"

namespace heu::lib::algorithms::paillier_ipcl {
bool SecretKey::operator==(const SecretKey &other) const {
  return ipcl_prikey_.getP() == other.ipcl_prikey_.getP() &&
         ipcl_prikey_.getQ() == other.ipcl_prikey_.getQ() &&
         ipcl_prikey_.getLambda() == other.ipcl_prikey_.getLambda();
}

bool SecretKey::operator!=(const SecretKey &other) const {
  return !this->operator==(other);
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

}  // namespace heu::lib::algorithms::paillier_ipcl
