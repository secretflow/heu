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

#include "heu/algorithms/incubator/ishe/base.h"

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

SecretKey::SecretKey(std::tuple<MPInt, MPInt, MPInt> in) {
  this->s_ = std::move(std::get<0>(in));
  this->p_ = std::move(std::get<1>(in));
  this->L_ = std::move(std::get<2>(in));
}

PublicKey::PublicKey(std::tuple<long, long, long, MPInt> in) {
  this->k_0 = std::get<0>(in);
  this->k_r = std::get<1>(in);
  this->k_M = std::get<2>(in);
  this->N = std::move(std::get<3>(in));
  MPInt::Pow(MPInt(2), k_M - 1, &this->M[1]);
  this->M[0] = -this->M[1];
}

PublicKey::PublicKey(std::tuple<long, long, long, MPInt, std::vector<MPInt>,
                                std::vector<MPInt>, std::vector<MPInt>>
                         in)
    : PublicKey(std::make_tuple(std::get<0>(in), std::get<1>(in),
                                std::get<2>(in), std::get<3>(in))) {
  this->ADDONES = std::get<4>(in);
  this->ONES = std::get<5>(in);
  this->NEGS = std::get<6>(in);
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
