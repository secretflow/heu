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

#include "heu/algorithms/paillier_zahlen/base.h"

namespace heu::algos::paillier_z {

namespace {
size_t kExpUnitBits = 10;
}  // namespace

void PublicKey::Init() {
  n_square_ = n_ * n_;
  n_half_ = n_ / 2;
  key_size_ = n_.BitCount();

  m_space_ = BigInt::CreateMontgomerySpace(n_square_);
  hs_table_ = std::make_shared<BaseTable>();
  size_t word_size = m_space_->GetWordBitSize();
  m_space_->MakeBaseTable(
      h_s_, kExpUnitBits,
      // make max_exp_bits divisible by word_size
      (key_size_ / 2 + word_size - 1) / word_size * word_size, hs_table_.get());
}

void SecretKey::Init() {
  p_square_ = p_ * p_;  // p^2
  q_square_ = q_ * q_;  // q^2
  n_square_ = p_square_ * q_square_;
  BigInt q_square_inv = q_square_.InvMod(p_square_);
  q_square_inv_mul_q_square_ =
      q_square_inv * q_square_;   // [(q^2)^{-1} mod p^2] * q^2
  p_inv_mod_q_ = p_.InvMod(q_);   // p^{-1} mod q
  phi_p_square_ = p_ * (p_ - 1);  // p(p-1)
  phi_q_square_ = q_ * (q_ - 1);  // q(q-1)
  phi_p_ = p_ - 1;                // p-1
  phi_q_ = q_ - 1;                // q-1

  // Precompute hp
  BigInt n = p_ * q_;
  BigInt g = n + 1;
  hp_ = g.PowMod(phi_p_, p_square_);
  hp_ = (hp_ - 1) / p_;
  hp_ = hp_.InvMod(p_);

  // Precompute hq
  hq_ = g.PowMod(phi_q_, q_square_);
  hq_ = (hq_ - 1) / q_;
  hq_ = hq_.InvMod(q_);
}

BigInt SecretKey::PowModNSquareCrt(const BigInt &base,
                                   const BigInt &exp) const {
  // smaller exponents: exp mod p(p-1), exp mod q(q-1)
  BigInt pexp = exp % phi_p_square_;
  BigInt qexp = exp % phi_q_square_;

  // smaller bases: mod p^2, q^2
  BigInt pbase = base % p_square_;
  BigInt qbase = base % q_square_;

  // smaller exponentiations of base mod p^2, q^2
  BigInt pbase_exp = pbase.PowMod(pexp, p_square_);
  BigInt qbase_exp = qbase.PowMod(qexp, q_square_);

  // CRT to calculate base^exp mod n^2
  return ((pbase_exp - qbase_exp) * q_square_inv_mul_q_square_ + qbase_exp) %
         n_square_;
}

Plaintext ItemTool::Clone(const Plaintext &pt) const { return pt; }

Ciphertext ItemTool::Clone(const Ciphertext &ct) const {
  return Ciphertext(ct.c_);
}

}  // namespace heu::algos::paillier_z
