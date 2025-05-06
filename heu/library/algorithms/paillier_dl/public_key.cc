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

#include "heu/library/algorithms/paillier_dl/public_key.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::paillier_dl {

void PublicKey::Init(const MPInt &n, MPInt *g) {
  n_ = n;
  CGBNWrapper::StoreToDev(this);

  CGBNWrapper::InitPK(this);
  CGBNWrapper::StoreToHost(this);
  *g = g_;
  half_n_ = n_ / MPInt(2);
}

std::string PublicKey::ToString() const {
  return fmt::format(
      "DL-paillier PK: n={}[{}bits], max_plaintext={}[~{}bits]",
      n_.ToHexString(), n_.BitCount(),  max_int_.ToHexString(), max_int_.BitCount());
}

PublicKey::PublicKey(){
  CGBNWrapper::DevMalloc(this);
}

PublicKey::~PublicKey(){
  CGBNWrapper::DevFree(this);
}

PublicKey::PublicKey(const PublicKey& other) {
  this->g_ = other.g_;
  this->n_ = other.n_;
  this->nsquare_ = other.nsquare_;
  this->max_int_ = other.max_int_;
  this->half_n_ = other.half_n_;
  CGBNWrapper::DevMalloc(this);
  CGBNWrapper::DevCopy(this, other);
}

PublicKey& PublicKey::operator=(const PublicKey& other) {
  if (this != &other) {
    this->g_ = other.g_;
    this->n_ = other.n_;
    this->nsquare_ = other.nsquare_;
    this->max_int_ = other.max_int_;
    this->half_n_ = other.half_n_;
    CGBNWrapper::DevCopy(this, other);
  }
  return *this;
}

PublicKey::PublicKey(PublicKey&& other) noexcept {
  this->g_ = other.g_;
  this->n_ = other.n_;
  this->nsquare_ = other.nsquare_;
  this->max_int_ = other.max_int_;
  this->half_n_ = other.half_n_;
  this->dev_g_ = other.dev_g_;
  this->dev_n_ = other.dev_n_;
  this->dev_nsquare_ = other.dev_nsquare_;
  this->dev_max_int_ = other.dev_max_int_;
  this->dev_pk_ = other.dev_pk_;

  other.dev_g_ = nullptr;
  other.dev_n_ = nullptr;
  other.dev_nsquare_ = nullptr;
  other.dev_max_int_ = nullptr;
  other.dev_pk_ = nullptr;
}

PublicKey& PublicKey::operator=(PublicKey&& other) noexcept {
  if (this != &other) {
    CGBNWrapper::DevFree(this);
    
    this->g_ = other.g_;
    this->n_ = other.n_;
    this->nsquare_ = other.nsquare_;
    this->max_int_ = other.max_int_;
    this->half_n_ = other.half_n_;
    this->dev_g_ = other.dev_g_;
    this->dev_n_ = other.dev_n_;
    this->dev_nsquare_ = other.dev_nsquare_;
    this->dev_max_int_ = other.dev_max_int_;
    this->dev_pk_ = other.dev_pk_;

    other.dev_g_ = nullptr;
    other.dev_n_ = nullptr;
    other.dev_nsquare_ = nullptr;
    other.dev_max_int_ = nullptr;
    other.dev_pk_ = nullptr;
  }
  return *this;
}

}  // namespace heu::lib::algorithms::paillier_dl
