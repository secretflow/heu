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

void invert(mpz_t rop, mpz_t a, mpz_t b) {
  mpz_invert(rop, a, b);
}

void h_func_gmp(mpz_t rop, mpz_t g, mpz_t x, mpz_t xsquare) {
  mpz_t tmp;
  mpz_init(tmp);
  mpz_sub_ui(tmp, x, 1);
  mpz_powm(rop, g, tmp, xsquare); 
  mpz_sub_ui(rop, rop, 1);
  mpz_div(rop, rop, x);
  mpz_invert(rop, rop, x);
  mpz_clear(tmp); 
}

void SecretKey::Init(mpz_t g, mpz_t raw_p, mpz_t raw_q) {
  mpz_init(p_);
  mpz_init(q_);
  mpz_init(psquare_);
  mpz_init(qsquare_);
  mpz_init(q_inverse_);
  mpz_init(hp_);
  mpz_init(hq_);
  
  if(mpz_cmp(raw_q, raw_p) < 0) {
    mpz_set(p_, raw_q);
    mpz_set(q_, raw_p);
  } else {
    mpz_set(p_, raw_p);
    mpz_set(q_, raw_q);
  }
  mpz_mul(psquare_, p_, p_);
  mpz_mul(qsquare_, q_, q_);
  invert(q_inverse_, q_, p_);
  h_func_gmp(hp_, g, p_, psquare_); 
  h_func_gmp(hq_, g, q_, qsquare_); 
  CGBNWrapper::DevMalloc(this);
  CGBNWrapper::StoreToDev(this);
}

std::string SecretKey::ToString() const {
  NOT_SUPPORT;
  // return fmt::format("Z-paillier SK: p={}[{}bits], q={}[{}bits]",
  //                    p_.ToHexString(), p_.BitCount(), q_.ToHexString(),
  //                    q_.BitCount());
}

}  // namespace heu::lib::algorithms::paillier_z
