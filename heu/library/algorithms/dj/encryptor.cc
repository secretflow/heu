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

#include "heu/library/algorithms/dj/encryptor.h"

#include "fmt/compile.h"

namespace heu::lib::algorithms::dj {

Ciphertext Encryptor::EncryptZero() const {
  return Ciphertext{pk_.RandomZnStar()};
}

Ciphertext Encryptor::Encrypt(const Plaintext &m) const {
  YACL_ENFORCE(m.CompareAbs(pk_.PlaintextBound()) < 0,
               "message number out of range, message={}, max (abs)={}", m,
               pk_.PlaintextBound());
  Ciphertext ctR;
  pk_.MulMod(pk_.Encrypt(m), pk_.RandomZnStar(), &ctR.c_);
  return ctR;
}

std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const Plaintext &m) const {
  MPInt g_m{pk_.Encrypt(m)}, r_n_s{pk_.RandomZnStar()}, ctR;
  pk_.MulMod(g_m, r_n_s, &ctR);
  auto audit_str{fmt::format(FMT_COMPILE("p:{},rn:{},c:{}"), m.ToHexString(),
                             r_n_s.ToHexString(), ctR.ToHexString())};
  return {Ciphertext{ctR}, audit_str};
}

}  // namespace heu::lib::algorithms::dj
