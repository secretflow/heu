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

#include "heu/library/algorithms/dgk/secret_key.h"

namespace heu::lib::algorithms::dgk {

void SecretKey::Init(const MPInt &p, const MPInt &q, const MPInt &vp,
                     const MPInt &vq, const MPInt &u, const MPInt &g) {
  p_ = p;
  q_ = q;
  vp_ = vp;
  vq_ = vq;
  u_ = u;
  g_ = g;
  log_table_ =
      std::make_shared<std::unordered_map<MPInt, MPInt>>(u.Get<size_t>());
  MPInt qm{g.PowMod(vp, p)}, ct{1};
  log_table_->emplace(ct, MPInt{0});
  for (MPInt i{1}; i < u; i.IncrOne()) {
    ct = ct.MulMod(qm, p);
    log_table_->emplace(ct, i);
  }
}

bool SecretKey::operator==(const SecretKey &sk) const {
  return p_ == sk.p_ && q_ == sk.q_ && vp_ == sk.vp_ && vq_ == sk.vq_ &&
         u_ == sk.u_ && g_ == sk.g_;
}

bool SecretKey::operator!=(const SecretKey &sk) const { return !(*this == sk); }

std::string SecretKey::ToString() const {
  return fmt::format(
      "Damgard-Geisler-Krøigaard SK: p={}[{}bits], q={}[{}bits], "
      "vp={}[{}bits], vq={}[{}bits], u={}, g={}",
      p_.ToHexString(), p_.BitCount(), q_.ToHexString(), q_.BitCount(),
      vp_.ToHexString(), vp_.BitCount(), vq_.ToHexString(), vq_.BitCount(),
      u_.ToHexString(), g_.ToHexString());
}

MPInt SecretKey::Decrypt(const MPInt &ct) const {
  auto it = log_table_->find((ct % p_).PowMod(vp_, p_));
  YACL_ENFORCE(it != log_table_->end(), "SecretKey: Invalid ciphertext");
  return it->second;
}

}  // namespace heu::lib::algorithms::dgk
