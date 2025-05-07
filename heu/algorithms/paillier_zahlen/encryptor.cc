// Copyright 2024 Ant Group Co., Ltd.
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

#include "heu/algorithms/paillier_zahlen/encryptor.h"

#include "fmt/compile.h"

namespace heu::algos::paillier_z {

Ciphertext Encryptor::EncryptZeroT() const { return Ciphertext(GetRn()); }

Ciphertext Encryptor::Encrypt(const Plaintext &m) const {
  return EncryptImpl(m);
}

void Encryptor::Encrypt(const Plaintext &m, Ciphertext *out) const {
  *out = EncryptImpl(m);
}

void Encryptor::EncryptWithAudit(const Plaintext &m, Ciphertext *ct_out,
                                 std::string *audit_out) const {
  *ct_out = EncryptImpl<true>(m, audit_out);
}

BigInt Encryptor::GetRn() const {
  BigInt r = BigInt::RandomExactBits(pk_->key_size_ / 2);

  // (h_s_)^r
  return pk_->m_space_->PowMod(*pk_->hs_table_, r);
}

template <bool audit>
Ciphertext Encryptor::EncryptImpl(const BigInt &m,
                                  std::string *audit_str) const {
  YACL_ENFORCE(m.CompareAbs(pk_->PlaintextBound()) <= 0,
               "message number out of range, message={}, max (abs)={}", m,
               pk_->PlaintextBound());

  // Note: g^m = (1 + n)^m = (1 + n*m) mod n^2
  // It is also correct when m is negative
  BigInt gm = pk_->n_ * m + 1;  // no need mod

  pk_->m_space_->MapIntoMSpace(gm);
  Ciphertext ct;
  auto rn = GetRn();
  ct.c_ = pk_->m_space_->MulMod(gm, rn);
  if constexpr (audit) {
    YACL_ENFORCE(audit_str != nullptr);
    *audit_str = fmt::format(FMT_COMPILE("p:{},rn:{},c:{}"), m.ToHexString(),
                             rn.ToHexString(), ct.c_.ToHexString());
  }
  return ct;
}

}  // namespace heu::algos::paillier_z
