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

#include "heu/library/algorithms/paillier_zahlen/public_key.h"

namespace heu::lib::algorithms::paillier_z {

namespace {
size_t kExpUnitBits = 10;
}  // namespace

void SetCacheTableDensity(size_t density) {
  NOT_SUPPORT;
  // YACL_ENFORCE(density > 0, "density must > 0");
  // kExpUnitBits = density;
}

void PublicKey::Init(mpz_t &n, mpz_t g) {
  mpz_init(nsquare_);
  mpz_init(max_int_);
  mpz_add_ui(g, n, 1); 
  mpz_mul(nsquare_, n, n);
  mpz_div_ui(max_int_, n, 3);
  mpz_sub_ui(max_int_, max_int_, 1);
  *n_ = *n;
  *g_ = *g;

  CGBNWrapper::DevMalloc(this);
  CGBNWrapper::StoreToDev(this);
}

std::string PublicKey::ToString() const {
  NOT_SUPPORT;
  // return fmt::format(
  //     "Z-paillier PK: n={}[{}bits], h_s={}, max_plaintext={}[~{}bits]",
  //     n_.ToHexString(), n_.BitCount(), h_s_.ToHexString(),
  //     PlaintextBound().ToHexString(), PlaintextBound().BitCount());
}

}  // namespace heu::lib::algorithms::paillier_z
