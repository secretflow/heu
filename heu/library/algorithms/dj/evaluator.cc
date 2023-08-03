// Copyright 2023 Ant Group Co., Ltd.
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

#include "heu/library/algorithms/dj/evaluator.h"

#include "heu/library/algorithms/util/he_assert.h"

namespace heu::lib::algorithms::dj {

#define VALIDATE(ct)                                         \
  HE_ASSERT(!(ct).IsNegative() && (ct) < pk_.CipherModule(), \
            "Evaluator: Invalid ciphertext")

void Evaluator::Randomize(Ciphertext* ct) const {
  VALIDATE(*ct);
  pk_.MulMod(*ct, pk_.RandomZnStar(), ct);
}

Ciphertext Evaluator::Add(const Ciphertext& a, const Ciphertext& b) const {
  VALIDATE(a);
  VALIDATE(b);
  Ciphertext c;
  pk_.MulMod(a, b, &c);
  return c;
}

Ciphertext Evaluator::Mul(const Ciphertext& a, const Plaintext& p) const {
  VALIDATE(a);
  return p.IsZero()          ? encryptor_.EncryptZero()
         : p == Plaintext{1} ? a
                             : Ciphertext{pk_.Encode(pk_.Decode(a).PowMod(
                                   p, pk_.CipherModule()))};
}

}  // namespace heu::lib::algorithms::dj
