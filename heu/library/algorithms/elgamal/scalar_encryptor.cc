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

#include "heu/library/algorithms/elgamal/scalar_encryptor.h"

#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::elgamal {

Encryptor::Encryptor(const PublicKey& pk) : pk_(pk) {
  Ciphertext::EnableEcGroup(pk_.GetCurve());
}

Ciphertext Encryptor::EncryptZero() const {
  MPInt r;
  MPInt::RandomLtN(pk_.GetCurve()->GetOrder(), &r);
  return Ciphertext(pk_.GetCurve(), pk_.GetCurve()->MulBase(r),
                    pk_.GetCurve()->Mul(pk_.GetH(), r));
}

Ciphertext Encryptor::Encrypt(const Plaintext& m) const {
  YACL_ENFORCE(m.CompareAbs(pk_.PlaintextBound()) <= 0,
               "message number out of range, message={}, max (abs)={}", m,
               pk_.PlaintextBound());

  MPInt r;
  MPInt::RandomLtN(pk_.GetCurve()->GetOrder(), &r);
  return Ciphertext(pk_.GetCurve(), pk_.GetCurve()->MulBase(r),
                    pk_.GetCurve()->MulDoubleBase(m, r, pk_.GetH()));
}

std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const Plaintext& m) const {
  YACL_ENFORCE(m.CompareAbs(pk_.PlaintextBound()) <= 0,
               "message number out of range, message={}, max (abs)={}", m,
               pk_.PlaintextBound());

  MPInt r;
  MPInt::RandomLtN(pk_.GetCurve()->GetOrder(), &r);
  auto c1 = pk_.GetCurve()->MulBase(r);
  auto c2 = pk_.GetCurve()->MulDoubleBase(m, r, pk_.GetH());
  auto str = fmt::format("p:{};r:{};c1:{};c2:{}", m, r,
                         pk_.GetCurve()->GetAffinePoint(c1),
                         pk_.GetCurve()->GetAffinePoint(c2));
  return {Ciphertext(pk_.GetCurve(), c1, c2), str};
}

}  // namespace heu::lib::algorithms::elgamal
