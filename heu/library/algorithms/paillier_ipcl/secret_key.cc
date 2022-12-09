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

#include "heu/library/algorithms/paillier_ipcl/secret_key.h"

namespace heu::lib::algorithms::paillier_ipcl {
bool SecretKey::operator==(const SecretKey &other) const {
  return ipcl_prikey_.getP() == other.ipcl_prikey_.getP()
          && ipcl_prikey_.getQ() == other.ipcl_prikey_.getQ()
          && ipcl_prikey_.getLambda() == other.ipcl_prikey_.getLambda();
}

bool SecretKey::operator!=(const SecretKey &other) const {
  return !this->operator==(other);
}

std::string SecretKey::ToString() const {
  std::string lambda;
  ipcl_prikey_.getLambda().num2hex(lambda);
  return fmt::format("IPCL secret key: lambda={}[{}bits]",
                  lambda, ipcl_prikey_.getLambda().BitSize());
}

}  // namespace heu::lib::algorithms::paillier_ipcl
