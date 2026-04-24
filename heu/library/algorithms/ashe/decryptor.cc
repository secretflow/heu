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

#include "heu/library/algorithms/ashe/decryptor.h"

namespace heu::lib::algorithms::ashe {
void Decryptor::Decrypt(const Ciphertext &ct, Plaintext *out) const {
  *out = Decrypt(ct);
}

Plaintext Decryptor::Decrypt(const Ciphertext &ct) const {
  BigInt tmp = ct.n_.AddMod(ZERO, p).AddMod(ZERO, q).AddMod(ZERO, MAX);
  return tmp <= half ? tmp : tmp - MAX;
}
}  // namespace heu::lib::algorithms::ashe
