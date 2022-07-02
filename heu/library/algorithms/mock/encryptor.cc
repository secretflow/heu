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

#include "heu/library/algorithms/mock/encryptor.h"

namespace heu::lib::algorithms::mock {

Ciphertext Encryptor::EncryptZero() const {
  Ciphertext res;
  res.c_ = MPInt(0);
  return res;
}

Ciphertext Encryptor::Encrypt(const MPInt& m) const {
  YASL_ENFORCE(m.CompareAbs(pk_.PlaintextBound()) < 0,
               "message number out of range, message={}, max (abs)={}",
               m.ToHexString(), pk_.PlaintextBound());

  Ciphertext res;
  res.c_ = m;
  return res;
}

std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const MPInt& m) const {
  Ciphertext res;
  res.c_ = m;
  return {res, "mock"};
}

}  // namespace heu::lib::algorithms::mock
