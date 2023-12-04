// Copyright 2023 Denglin Co., Ltd.
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

#include "heu/library/algorithms/paillier_dl/encryptor.h"
#include "heu/library/algorithms/paillier_dl/cgbn_wrapper/cgbn_wrapper.h"
#include "fmt/compile.h"
#include "fmt/format.h"

namespace heu::lib::algorithms::paillier_dl {

Encryptor::Encryptor(PublicKey pk) : pk_(std::move(pk)) {}
Encryptor::Encryptor(const Encryptor &from) : Encryptor(from.pk_) {}

template <bool audit>
std::vector<Ciphertext> Encryptor::EncryptImplVector(ConstSpan<Plaintext> pts,
                                                     std::vector<std::string> *audit_str) const {
  // printf("[warning] comment the EncryptImpl check.\n");
  // YACL_ENFORCE(m.CompareAbs(pk_.PlaintextBound()) < 0,
  //              "message number out of range, message={}, max (abs)={}",
  //              m.ToHexString(), pk_.PlaintextBound());
  std::vector<MPInt> rns;
  std::vector<Ciphertext> cts;
  std::vector<Plaintext> handled_pts;
  for (int i=0; i<pts.size(); i++) {
    // handle negative
    MPInt tmp_pt(*pts[i]);
    if (pts[i]->IsNegative()) {
      tmp_pt += pk_.n_;
    }
    handled_pts.push_back(tmp_pt);

    Ciphertext ct;
    MPInt rn;
    cts.push_back(ct);
    rns.push_back(rn);
  }
  CGBNWrapper::Encrypt(handled_pts, pk_, rns, cts);


  // if constexpr (audit) {
  //   YACL_ENFORCE(audit_str != nullptr);
  //   *audit_str = fmt::format(FMT_COMPILE("p:{},rn:{},c:{}"), m.ToHexString(),
  //                            rn.ToHexString(), ct.c_.ToHexString());
  // }
  return cts;
}

std::vector<Ciphertext> Encryptor::Encrypt(ConstSpan<Plaintext> pts) const { 
  return EncryptImplVector(pts); 
}

std::pair<std::vector<Ciphertext>, std::vector<std::string>> Encryptor::EncryptWithAudit(
      ConstSpan<Plaintext> pts) const {
  std::vector<std::string> audit_str;
  auto c = EncryptImplVector<true>(pts, &audit_str);
  return std::make_pair(c, audit_str);
}
}  // namespace heu::lib::algorithms::paillier_dl
