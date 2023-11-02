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

namespace {
size_t kExpUnitBits = 10;
}  // namespace

void SetCacheTableDensity(size_t density) {
  NOT_SUPPORT;
  // YACL_ENFORCE(density > 0, "density must > 0");
  // kExpUnitBits = density;
}


void PublicKey::Init(MPInt &n, MPInt &g) {
  n_ = n;
  CGBNWrapper::DevMalloc(this);
  CGBNWrapper::StoreToDev(this);

  CGBNWrapper::InitPK(this);
  CGBNWrapper::StoreToHost(this);
  g = g_;
  half_n_ = n_ / MPInt(2);
}

std::string PublicKey::ToString() const {
  NOT_SUPPORT;
  // return fmt::format(
  //     "Z-paillier PK: n={}[{}bits], h_s={}, max_plaintext={}[~{}bits]",
  //     n_.ToHexString(), n_.BitCount(), h_s_.ToHexString(),
  //     PlaintextBound().ToHexString(), PlaintextBound().BitCount());
}

}  // namespace heu::lib::algorithms::paillier_dl
