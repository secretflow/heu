// Copyright 2024 CyberChangAn Group, Xidian University.
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

#include "heu/algorithms/incubator/ishe/encryptor.h"

#include <string>

namespace heu::algos::ishe {

Ciphertext Encryptor::EncryptZeroT() const {
  return Encrypt(MPInt(0), MPInt(1));
}

template <bool audit>
Ciphertext Encryptor::EncryptImpl(const Plaintext &m, const MPInt &d,
                                  std::string *audit_out) const {
  YACL_ENFORCE(m < pp_->MessageSpace()[1] && m >= pp_->MessageSpace()[0],
               "Plaintext {} is too large, cannot encrypt.", m.ToString());
  MPInt r, r1;
  MPInt::RandomExactBits(pp_->k_r, &r);           // r = {0,1}^k_r
  MPInt::RandomExactBits(pp_->k_0, &r1);          // r' ={0,1}^k_0
  MPInt m1 = sk_->getS().PowMod(d, pp_->getN());  // m' = s^d
  m1 *= (r * sk_->getL() + m);                    // m' = s*(rL+m)
  m1 = m1.MulMod((MPInt(1) + r1 * sk_->getP()), pp_->getN());
  // m' = s*(rL+m)*(1+r'p) mod N
  if constexpr (audit) {
    YACL_ENFORCE(audit_out != nullptr);
    *audit_out =
        fmt::format("r:{}\n r':{}\n", r.ToHexString(), r1.ToHexString());
  }
  return Ciphertext(m1, d);
}

Ciphertext Encryptor::Encrypt(const Plaintext &m, const MPInt &d) const {
  return EncryptImpl(m, d, nullptr);
}

Ciphertext Encryptor::Encrypt(const Plaintext &m) const {
  return Encrypt(m, MPInt(1));
}

void Encryptor::Encrypt(const Plaintext &m, Ciphertext *out) const {
  *out = Encrypt(m);
}

void Encryptor::EncryptWithAudit(const Plaintext &m, Ciphertext *ct_out,
                                 std::string *audit_out) const {
  *ct_out = EncryptImpl<true>(m, 1_mp, audit_out);
  audit_out->assign(
      fmt::format("pt:{}\n ct:{}", m.ToString(), ct_out->n_.ToString()));
}

}  // namespace heu::algos::ishe
