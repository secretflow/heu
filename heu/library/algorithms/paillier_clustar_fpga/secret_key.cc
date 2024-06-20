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

#include "heu/library/algorithms/paillier_clustar_fpga/secret_key.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

SecretKey::SecretKey(const PublicKey &pub_key, const MPInt &p, const MPInt &q) {
  YACL_ENFORCE(p * q == pub_key.GetN(),
               "given public key does not match the given p and q");
  YACL_ENFORCE(p != q, "p and q have to be different");

  this->pub_key_ = pub_key;
  if (q < p) {
    this->p_ = q;
    this->q_ = p;
  } else {
    this->p_ = p;
    this->q_ = q;
  }

  MPInt::Mul(this->p_, this->p_, &p_square_);
  MPInt::Mul(this->q_, this->q_, &q_square_);

  MPInt::InvertMod(this->q_, this->p_, &q_inverse_);
  HFunc(p_, p_square_, hp_);
  HFunc(q_, q_square_, hq_);
}

void SecretKey::HFunc(const MPInt &x, const MPInt &x_square, MPInt &result) {
  // 1 powmod
  MPInt res_pow_mod;
  MPInt::PowMod(pub_key_.GetG(), x - MPInt::_1_, x_square, &res_pow_mod);

  // 2 l_func
  MPInt res_l_func = (res_pow_mod - MPInt::_1_) / x;

  // 3 invert
  MPInt::InvertMod(res_l_func, x, &result);
}

bool SecretKey::operator==(const SecretKey &other) const {
  return pub_key_ == other.pub_key_ && p_ == other.p_ && q_ == other.q_ &&
         p_square_ == other.p_square_ && q_square_ == other.q_square_ &&
         q_inverse_ == other.q_inverse_ && hp_ == other.hp_ && hq_ == other.hq_;
}

bool SecretKey::operator!=(const SecretKey &other) const {
  return !this->operator==(other);
}

std::string SecretKey::ToString() const {
  return fmt::format("clustar fpga secret key: p = {}[{}bits], q = {}[{}bits]",
                     p_.ToHexString(), p_.BitCount(), q_.ToHexString(),
                     q_.BitCount());
}

// Functions for unit test
const MPInt &SecretKey::GetP() const { return p_; }

const MPInt &SecretKey::GetQ() const { return q_; }

const MPInt &SecretKey::GetPSquare() const { return p_square_; }

const MPInt &SecretKey::GetQSquare() const { return q_square_; }

const MPInt &SecretKey::GetQInverse() const { return q_inverse_; }

const MPInt &SecretKey::GetHP() const { return hp_; }

const MPInt &SecretKey::GetHQ() const { return hq_; }

const PublicKey &SecretKey::GetPubKey() const { return pub_key_; }

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
