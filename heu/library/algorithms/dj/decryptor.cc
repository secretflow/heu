// Copyright 2023 zhangwfjh
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

#include "heu/library/algorithms/dj/decryptor.h"

#include "heu/library/algorithms/util/he_assert.h"

namespace heu::lib::algorithms::dj {

Plaintext Decryptor::Decrypt(const Ciphertext& ct) const {
  HE_ASSERT(!ct.c_.IsNegative() && ct.c_ < pk_.CipherModule(),
            "Decryptor: Invalid ciphertext");
  Plaintext m{sk_.Decrypt(pk_.Decode(ct.c_))};
  return m >= pk_.PlaintextBound() ? m - pk_.PlainModule() : m;
}

}  // namespace heu::lib::algorithms::dj
