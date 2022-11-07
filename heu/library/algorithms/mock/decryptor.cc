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

#include "heu/library/algorithms/mock/decryptor.h"

namespace heu::lib::algorithms::mock {

void Decryptor::Decrypt(const Ciphertext& ct, Plaintext* out) const {
  out->Set(ct.c_);
}

Plaintext Decryptor::Decrypt(const Ciphertext& ct) const {
  Plaintext pt;
  pt.Set(ct.c_);
  return pt;
}

}  // namespace heu::lib::algorithms::mock
