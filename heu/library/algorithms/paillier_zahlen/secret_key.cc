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

#include "heu/library/algorithms/paillier_zahlen/secret_key.h"

namespace heu::lib::algorithms::paillier_z {

void SecretKey::Init() {
  p_square_ = p_ * p_;  // p^2
  q_square_ = q_ * q_;  // q^2
  n_square_ = p_square_ * q_square_;
  MPInt q_square_inv;
  MPInt::InvertMod(q_square_, p_square_, &q_square_inv);
  q_square_inv_mul_q_square_ =
      q_square_inv * q_square_;   // [(q^2)^{-1} mod p^2] * q^2
  phi_p_square_ = p_ * (p_ - 1);  // p(p-1)
  phi_q_square_ = q_ * (q_ - 1);  // q(q-1)
}

MPInt SecretKey::PowModNSquareCrt(const MPInt& base, const MPInt& exp) const {
  // smaller exponents: exp mod p(p-1), exp mod q(q-1)
  MPInt pexp = exp % phi_p_square_;
  MPInt qexp = exp % phi_q_square_;

  // smaller bases: mod p^2, q^2
  MPInt pbase = base % p_square_;
  MPInt qbase = base % q_square_;

  // smaller exponentiations of base mod p^2, q^2
  MPInt pbase_exp, qbase_exp;
  MPInt::PowMod(pbase, pexp, p_square_, &pbase_exp);
  MPInt::PowMod(qbase, qexp, q_square_, &qbase_exp);

  // CRT to calculate base^exp mod n^2
  MPInt result =
      ((pbase_exp - qbase_exp) * q_square_inv_mul_q_square_ + qbase_exp) %
      n_square_;
  return result;
}

std::string SecretKey::ToString() const {
  return fmt::format("Z-paillier secret key: lambda={}[{}bits], μ={}[{}bits]",
                     lambda_.ToHexString(), lambda_.BitCount(),
                     mu_.ToHexString(), mu_.BitCount());
}

}  // namespace heu::lib::algorithms::paillier_z
