
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

#include "heu/algorithms/ishe/base.h"

#include "yacl/utils/serializer.h"

namespace heu::algos::ishe {

Plaintext ItemTool::Clone(const Plaintext &pt) const { return pt; }

Ciphertext ItemTool::Clone(const Ciphertext &ct) const {
  return Ciphertext(ct.n_, ct.d_);
}

std::string Ciphertext::ToString() const {
  return fmt::format("CT: ({},{})", n_, d_);
}

SecretKey::SecretKey(MPInt s, MPInt p, MPInt L) {
  this->s_ = std::move(s);
  this->p_ = std::move(p);
  this->L_ = std::move(L);
}

PublicKey::PublicKey(const int k_0, const int k_r, MPInt M[2], MPInt N) {
  this->k_0 = k_0;
  this->k_r = k_r;
  this->N = std::move(N);
  this->M[0] = M[0];
  this->M[1] = M[1];
}

size_t ItemTool::Serialize(const Plaintext &pt, uint8_t *buf,
                           const size_t buf_len) const {
  return pt.Serialize(buf, buf_len);
}

size_t ItemTool::Serialize(const Ciphertext &ct, uint8_t *buf,
                           const size_t buf_len) const {
  return yacl::SerializeVarsTo(buf, buf_len, ct.n_, ct.d_);
}

yacl::Buffer ItemTool::Serialize(const Ciphertext &ct) {
  return yacl::SerializeVars(ct.n_, ct.d_);
}

Plaintext ItemTool::DeserializePT(const yacl::ByteContainerView buffer) const {
  Plaintext res;
  res.Deserialize(buffer);
  return res;
}

Ciphertext ItemTool::DeserializeCT(yacl::ByteContainerView buffer) const {
  Ciphertext ct;
  DeserializeVarsTo(buffer, &ct.n_, &ct.d_);
  return ct;
}

}  // namespace heu::algos::ishe
