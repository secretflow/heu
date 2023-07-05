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

#include "heu/library/algorithms/elgamal/scalar_decryptor.h"

namespace heu::lib::algorithms::elgamal {

void Decryptor::Decrypt(const Ciphertext &ct, Plaintext *out) const {
  auto mg = pk_.GetCurve()->Sub(ct.c2, pk_.GetCurve()->Mul(ct.c1, sk_.GetX()));

  // now we know G and mG, recover m by a lookup table
  out->Set(sk_.GetInitedLookupTable()->Search(mg));
}

Plaintext Decryptor::Decrypt(const Ciphertext &ct) const {
  auto mg = pk_.GetCurve()->Sub(ct.c2, pk_.GetCurve()->Mul(ct.c1, sk_.GetX()));

  // now we know G and mG, recover m by a lookup table
  return Plaintext(sk_.GetInitedLookupTable()->Search(mg));
}

}  // namespace heu::lib::algorithms::elgamal
