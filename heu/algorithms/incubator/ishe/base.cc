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

#include "heu/algorithms/incubator/ishe/base.h"

namespace heu::algos::ishe {

Plaintext ItemTool::Clone(const Plaintext &pt) const { return pt; }

Ciphertext ItemTool::Clone(const Ciphertext &ct) const {
  return Ciphertext(ct.n_, ct.d_);
}

size_t Ciphertext::Serialize(uint8_t *buf, size_t buf_len) const {
  return yacl::SerializeVarsTo(buf, buf_len, n_, d_);
}

yacl::Buffer Ciphertext::Serialize() const {
  return yacl::SerializeVars(n_, d_);
}

void Ciphertext::Deserialize(yacl::ByteContainerView buffer) {
  DeserializeVarsTo(buffer, &n_, &d_);
}

std::string Ciphertext::ToString() const {
  return fmt::format("CT: ({},{})", n_, d_);
}

SecretKey::SecretKey(MPInt s, MPInt p, MPInt L) {
  this->s_ = std::move(s);
  this->p_ = std::move(p);
  this->L_ = std::move(L);
}

size_t SecretKey::Serialize(uint8_t *buf, size_t buf_len) const {
  return yacl::SerializeVarsTo(buf, buf_len, s_, p_, L_);
}

std::shared_ptr<SecretKey> SecretKey::LoadFrom(yacl::ByteContainerView in) {
  auto sk = std::make_shared<SecretKey>();
  DeserializeVarsTo(in, &sk->s_, &sk->p_, &sk->L_);
  return sk;
}

PublicParameters::PublicParameters(int64_t k_0, int64_t k_r, int64_t k_M,
                                   const MPInt &N) {
  this->k_0 = k_0;
  this->k_r = k_r;
  this->k_M = k_M;
  Init();
  this->N = N;
}

PublicParameters::PublicParameters(int64_t k_0, int64_t k_r, int64_t k_M,
                                   const MPInt &N,
                                   const std::vector<MPInt> &ADDONES,
                                   const std::vector<MPInt> &ONES,
                                   const std::vector<MPInt> &NEGS)
    : PublicParameters(k_0, k_r, k_M, N) {
  this->ADDONES = ADDONES;
  this->ONES = ONES;
  this->NEGS = NEGS;
}

size_t PublicParameters::Serialize(uint8_t *buf, size_t buf_len) const {
  return yacl::SerializeVarsTo(buf, buf_len, k_0, k_r, k_M, N, ADDONES, ONES,
                               NEGS);
}

void PublicParameters::Init() {
  MPInt::Pow(MPInt(2), k_M - 1, &this->M[1]);
  this->M[0] = -this->M[1];
}

std::shared_ptr<PublicParameters> PublicParameters::LoadFrom(
    yacl::ByteContainerView in) {
  auto pp = std::make_shared<PublicParameters>();
  DeserializeVarsTo(in, &pp->k_0, &pp->k_r, &pp->k_M, &pp->N, &pp->ADDONES,
                    &pp->ONES, &pp->NEGS);
  pp->Init();
  return pp;
}

}  // namespace heu::algos::ishe
