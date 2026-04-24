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

#include "heu/library/algorithms/ashe/encryptor.h"

namespace heu::lib::algorithms::ashe {
Ciphertext Encryptor::EncryptZero() const { return Encrypt(BigInt(0)); }

Ciphertext Encryptor::Encrypt(const Plaintext &m) const {
  return EncryptImpl(m, nullptr);
}

void Encryptor::Encrypt(const Plaintext &m, Ciphertext *out) const {
  *out = Encrypt(m);
}

std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const Plaintext &m) const {
  std::string audit_out;
  Ciphertext ct_out = EncryptImpl<true>(m, &audit_out);
  audit_out.append(
      fmt::format("pt:{}\n ct:{}", m.ToString(), ct_out.n_.ToString()));
  return std::make_pair(ct_out, audit_out);
}

template <bool audit>
Ciphertext Encryptor::EncryptImpl(const Plaintext &m,
                                  std::string *audit_str) const {
  YACL_ENFORCE(m <= pp_.MessageSpace().second && m >= pp_.MessageSpace().first,
               "Plaintext {} is too large, cannot encrypt.", m);
  BigInt r, r1;
  BigInt::RandomExactBits(pp_.k_r1, &r);
  BigInt::RandomExactBits(pp_.k_r2, &r1);
  const BigInt m1 = r * sk_.p_ + r1 * sk_.q_ + m.AddMod(ZERO, MAX);

  if constexpr (audit) {
    YACL_ENFORCE(audit_str != nullptr);
    *audit_str =
        fmt::format("r:{}\n r':{}\n", r.ToHexString(), r1.ToHexString());
  }
  return Ciphertext(m1);
}
}  // namespace heu::lib::algorithms::ashe
