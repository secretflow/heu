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

#include "heu/library/algorithms/paillier_dl/secret_key.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::paillier_dl {

void SecretKey::Init(MPInt g, MPInt raw_p, MPInt raw_q) {
  g_ = g;
  if(raw_q < raw_p) {
    p_ = std::move(raw_q);
    q_ = std::move(raw_p);
  } else {
    p_ = std::move(raw_p);
    q_ = std::move(raw_q);
  }

  CGBNWrapper::StoreToDev(this);

  CGBNWrapper::InitSK(this);
  CGBNWrapper::StoreToHost(this);
}

std::string SecretKey::ToString() const {
  return fmt::format("DL-paillier SK: p={}[{}bits], q={}[{}bits]",
                     p_.ToHexString(), p_.BitCount(), q_.ToHexString(),
                     q_.BitCount());
}

SecretKey::SecretKey(){
  CGBNWrapper::DevMalloc(this);
}

SecretKey::~SecretKey(){
  CGBNWrapper::DevFree(this);
}

SecretKey::SecretKey(const SecretKey& other) {
  this->g_ = other.g_;
  this->p_ = other.p_;
  this->q_ = other.q_;
  this->psquare_ = other.psquare_;
  this->qsquare_ = other.qsquare_;
  this->q_inverse_ = other.q_inverse_;
  this->hp_ = other.hp_;
  this->hq_ = other.hq_;

  CGBNWrapper::DevMalloc(this);
  CGBNWrapper::DevCopy(this, other);
}

SecretKey& SecretKey::operator=(const SecretKey& other) {
  if (this != &other) {
    this->g_ = other.g_;
    this->p_ = other.p_;
    this->q_ = other.q_;
    this->psquare_ = other.psquare_;
    this->qsquare_ = other.qsquare_;
    this->q_inverse_ = other.q_inverse_;
    this->hp_ = other.hp_;
    this->hq_ = other.hq_;

    CGBNWrapper::DevCopy(this, other);
  }
  return *this;
}

SecretKey::SecretKey(SecretKey&& other) noexcept {
  this->g_ = other.g_;
  this->p_ = other.p_;
  this->q_ = other.q_;
  this->psquare_ = other.psquare_;
  this->qsquare_ = other.qsquare_;
  this->q_inverse_ = other.q_inverse_;
  this->hp_ = other.hp_;
  this->hq_ = other.hq_;
  this->dev_g_ = other.dev_g_;
  this->dev_p_ = other.dev_p_;
  this->dev_q_ = other.dev_q_;
  this->dev_psquare_ = other.dev_psquare_;
  this->dev_qsquare_ = other.dev_qsquare_;
  this->dev_q_inverse_ = other.dev_q_inverse_;
  this->dev_hp_ = other.dev_hp_;
  this->dev_hq_ = other.dev_hq_;
  
  this->dev_g_ = nullptr;
  this->dev_p_ = nullptr;
  this->dev_q_ = nullptr;
  this->dev_psquare_ = nullptr;
  this->dev_qsquare_ = nullptr;
  this->dev_q_inverse_ = nullptr;
  this->dev_hp_ = nullptr;
  this->dev_hq_ = nullptr;
}

SecretKey& SecretKey::operator=(SecretKey&& other) noexcept {
  if (this != &other) {
    CGBNWrapper::DevFree(this);
    
    this->g_ = other.g_;
    this->p_ = other.p_;
    this->q_ = other.q_;
    this->psquare_ = other.psquare_;
    this->qsquare_ = other.qsquare_;
    this->q_inverse_ = other.q_inverse_;
    this->hp_ = other.hp_;
    this->hq_ = other.hq_;
    this->dev_g_ = other.dev_g_;
    this->dev_p_ = other.dev_p_;
    this->dev_q_ = other.dev_q_;
    this->dev_psquare_ = other.dev_psquare_;
    this->dev_qsquare_ = other.dev_qsquare_;
    this->dev_q_inverse_ = other.dev_q_inverse_;
    this->dev_hp_ = other.dev_hp_;
    this->dev_hq_ = other.dev_hq_;
    
    this->dev_g_ = nullptr;
    this->dev_p_ = nullptr;
    this->dev_q_ = nullptr;
    this->dev_psquare_ = nullptr;
    this->dev_qsquare_ = nullptr;
    this->dev_q_inverse_ = nullptr;
    this->dev_hp_ = nullptr;
    this->dev_hq_ = nullptr;
  }
  return *this;
}
}  // namespace heu::lib::algorithms::paillier_dl
