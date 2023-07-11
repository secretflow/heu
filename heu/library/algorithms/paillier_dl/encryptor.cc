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

#include "heu/library/algorithms/paillier_zahlen/encryptor.h"

#include "fmt/compile.h"
#include "fmt/format.h"
#include "cgbn_wrapper/cgbn_wrapper.h"

namespace heu::lib::algorithms::paillier_z {

Encryptor::Encryptor(PublicKey pk) : pk_(std::move(pk)) {}
Encryptor::Encryptor(const Encryptor &from) : Encryptor(from.pk_) {}

MPInt Encryptor::GetRn() const {
  NOT_SUPPORT;
  // MPInt r;
  // MPInt::RandomExactBits(pk_.key_size_ / 2, &r);

  // // (h_s_)^r
  // MPInt out;
  // pk_.m_space_->PowMod(*pk_.hs_table_, r, &out);
  // return out;
}

Ciphertext Encryptor::EncryptZero() const { return Ciphertext(GetRn()); }

template <bool audit>
Ciphertext Encryptor::EncryptImplScalar(const MPInt &m,
                                  std::string *audit_str) const {
  printf("[warning] comment the EncryptImpl check.\n");
  // YACL_ENFORCE(m.CompareAbs(pk_.PlaintextBound()) < 0,
  //              "message number out of range, message={}, max (abs)={}",
  //              m.ToHexString(), pk_.PlaintextBound());
  MPInt rn;
  Ciphertext ct;
  CGBNWrapper::Encrypt(m, pk_, rn, ct);

  if constexpr (audit) {
    YACL_ENFORCE(audit_str != nullptr);
    *audit_str = fmt::format(FMT_COMPILE("p:{},rn:{},c:{}"), m.ToHexString(),
                             rn.ToHexString(), ct.c_.ToHexString());
  }
  return ct;
}

Ciphertext Encryptor::Encrypt(const MPInt &m) const { return EncryptImplScalar(m); }

template <bool audit>
std::vector<Ciphertext> Encryptor::EncryptImplVector(absl::Span<const Plaintext> pts,
                                                     std::vector<std::string> *audit_str) const {
  printf("[warning] comment the EncryptImpl check.\n");
  // YACL_ENFORCE(m.CompareAbs(pk_.PlaintextBound()) < 0,
  //              "message number out of range, message={}, max (abs)={}",
  //              m.ToHexString(), pk_.PlaintextBound());
  std::vector<MPInt> rns;
  std::vector<Ciphertext> cts;
  for (int i=0; i<pts.size(); i++) {
    Ciphertext ct;
    MPInt rn;
    cts.push_back(ct);
    rns.push_back(rn);
  }
  CGBNWrapper::Encrypt(pts, pk_, rns, cts);


  // if constexpr (audit) {
  //   YACL_ENFORCE(audit_str != nullptr);
  //   *audit_str = fmt::format(FMT_COMPILE("p:{},rn:{},c:{}"), m.ToHexString(),
  //                            rn.ToHexString(), ct.c_.ToHexString());
  // }
  return cts;
}


std::vector<Ciphertext> Encryptor::Encrypt(absl::Span<const Plaintext> pts) const { return EncryptImplVector(pts); }
std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const MPInt &m) const {
  std::string audit_str;
  auto c = EncryptImplScalar<true>(m, &audit_str);
  return {c, audit_str};
}

std::pair<std::vector<Ciphertext>, std::vector<std::string>> Encryptor::EncryptWithAudit(
      absl::Span<const Plaintext> pts) const {
  std::vector<std::string> audit_str;
  auto c = EncryptImplVector<true>(pts, &audit_str);
  return std::make_pair(c, audit_str);
}
}  // namespace heu::lib::algorithms::paillier_z
