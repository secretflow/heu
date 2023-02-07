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
  std::string lambda;
  ipcl_prikey_.getLambda().num2hex(lambda);
  return fmt::format("IPCL secret key: lambda={}[{}bits]", lambda,
                     ipcl_prikey_.getLambda().BitSize());
}

}  // namespace heu::lib::algorithms::paillier_ipcl
