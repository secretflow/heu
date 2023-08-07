// Copyright 2023 Clustar Technology Co., Ltd.
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

#include "public_key.h"

#include <limits>

namespace heu::lib::algorithms::paillier_clustar_fpga {

PublicKey::PublicKey(const PublicKey& pub_key) { InitCopy(pub_key); }

PublicKey::PublicKey(PublicKey&& pub_key) { InitMove(std::move(pub_key)); }

PublicKey::PublicKey(const MPInt& n) : n_(n) { Init(); }

PublicKey::PublicKey(MPInt&& n) : n_(std::move(n)) { Init(); }

PublicKey& PublicKey::operator=(const PublicKey& pub_key) {
  InitCopy(pub_key);
  return *this;
}

PublicKey& PublicKey::operator=(PublicKey&& pub_key) {
  InitMove(std::move(pub_key));
  return *this;
}

PublicKey& PublicKey::operator=(const MPInt& n) {
  n_ = n;
  Init();
  return *this;
}

PublicKey& PublicKey::operator=(MPInt&& n) {
  n_ = std::move(n);
  Init();
  return *this;
}

void PublicKey::Init() {
  g_ = n_ + MPInt::_1_;  // g_ = n_ + 1;

  MPInt::Mul(n_, n_, &n_square_);  // n_square_ = n_ * n_;

  MPInt max_int;
  MPInt::Div3(n_, &max_int);  //  n_ / 3
  max_int -= MPInt::_1_;      // max_int_ = n_ / 3 - 1;
  max_int_.Set(max_int);

  CalcPlaintextBound();
}

void PublicKey::InitCopy(const PublicKey& pub_key) {
  this->g_ = pub_key.g_;
  this->n_ = pub_key.n_;
  this->n_square_ = pub_key.n_square_;
  this->max_int_ = pub_key.max_int_;
  this->pt_bound_ = pub_key.pt_bound_;
}

void PublicKey::InitMove(PublicKey&& pub_key) {
  this->g_ = std::move(pub_key.g_);
  this->n_ = std::move(pub_key.n_);
  this->n_square_ = std::move(pub_key.n_square_);
  this->max_int_ = std::move(pub_key.max_int_);
  this->pt_bound_ = std::move(pub_key.pt_bound_);
}

bool PublicKey::operator==(const PublicKey& other) const {
  return n_ == other.n_ && g_ == other.g_ && n_square_ == other.n_square_ &&
         max_int_ == other.max_int_ && pt_bound_ == other.pt_bound_;
}

bool PublicKey::operator!=(const PublicKey& other) const {
  return !this->operator==(other);
}

std::string PublicKey::ToString() const {
  return fmt::format(
      "clustar fpga public key: n = {}[{}bits], max_plaintext={}[~{}bits]",
      n_.ToHexString(), n_.BitCount(), PlaintextBound().ToHexString(),
      PlaintextBound().BitCount());
}

const Plaintext& PublicKey::PlaintextBound() const& { return pt_bound_; }

void PublicKey::CalcPlaintextBound() {
  uint64_t max_val =
      static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1;
  pt_bound_.Set(max_val);
}

const MPInt& PublicKey::GetN() const { return n_; }

const MPInt& PublicKey::GetG() const { return g_; }

const MPInt& PublicKey::GetNSquare() const { return n_square_; }

const Plaintext PublicKey::GetMaxInt() const { return max_int_; }

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
