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

#include "heu/library/algorithms/mock/encryptor.h"

namespace heu::lib::algorithms::mock {

#ifdef IMPL_SCALAR_SPI
Ciphertext Encryptor::EncryptZero() const {
  Ciphertext res;
  res.bn_ = MPInt(0);
  return res;
}

Ciphertext Encryptor::Encrypt(const Plaintext& m) const {
  YASL_ENFORCE(m.bn_.CompareAbs(pk_.PlaintextBound().bn_) < 0,
               "message number out of range, message={}, max (abs)={}",
               m.bn_.ToHexString(), pk_.PlaintextBound());

  Ciphertext res;
  res.bn_ = m.bn_;
  return res;
}

std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const Plaintext& m) const {
  YASL_ENFORCE(m.bn_.CompareAbs(pk_.PlaintextBound().bn_) < 0,
               "message number out of range, message={}, max (abs)={}",
               m.bn_.ToHexString(), pk_.PlaintextBound());

  Ciphertext res;
  res.bn_ = m.bn_;
  return {res, fmt::format("mock:{}", m.bn_.ToString())};
}
#endif

#ifdef IMPL_VECTORIZED_SPI
std::vector<Ciphertext> Encryptor::EncryptZero(int64_t size) const {
  return std::vector<Ciphertext>(size, Ciphertext(MPInt(0)));
}

std::vector<Ciphertext> Encryptor::Encrypt(ConstSpan<Plaintext> pts) const {
  std::vector<Ciphertext> res;
  res.reserve(pts.size());
  for (size_t i = 0; i < pts.size(); ++i) {
    YASL_ENFORCE(pts[i]->bn_.CompareAbs(pk_.PlaintextBound().bn_) < 0,
                 "message number out of range, pts={}, max (abs)={}",
                 pts[i]->bn_.ToHexString(), pk_.PlaintextBound());

    res.emplace_back(pts[i]->bn_);
  }
  return res;
}

std::pair<std::vector<Ciphertext>, std::vector<std::string>>
Encryptor::EncryptWithAudit(ConstSpan<Plaintext> pts) const {
  std::vector<Ciphertext> res_c;
  res_c.reserve(pts.size());
  std::vector<std::string> res_s(pts.size());

  for (size_t i = 0; i < pts.size(); ++i) {
    YASL_ENFORCE(pts[i]->bn_.CompareAbs(pk_.PlaintextBound().bn_) < 0,
                 "message number out of range, pts={}, max (abs)={}",
                 pts[i]->bn_.ToHexString(), pk_.PlaintextBound());

    res_c.emplace_back(pts[i]->bn_);
    res_s.at(i) = fmt::format("mock:{}", pts[i]->bn_.ToString());
  }

  return {res_c, res_s};
}
#endif

}  // namespace heu::lib::algorithms::mock
