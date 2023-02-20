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

#include "heu/library/algorithms/ou/public_key.h"

namespace heu::lib::algorithms::ou {

namespace {
size_t kExpUnitBits = 10;
}  // namespace

void SetCacheTableDensity(size_t density) {
  YACL_ENFORCE(density > 0, "density must > 0");
  kExpUnitBits = density;
}

void PublicKey::Init() {
  MPInt::InvertMod(capital_g_, n_, &capital_g_inv_);

  // make cache table
  m_space_ = std::make_shared<MontgomerySpace>(n_);
  cg_table_ = std::make_shared<BaseTable>();
  cgi_table_ = std::make_shared<BaseTable>();
  ch_table_ = std::make_shared<BaseTable>();

  m_space_->MakeBaseTable(capital_g_, kExpUnitBits,
                          PlaintextBound().BitCount() - 1, cg_table_.get());
  m_space_->MakeBaseTable(capital_g_inv_, kExpUnitBits,
                          PlaintextBound().BitCount() - 1, cgi_table_.get());
  m_space_->MakeBaseTable(capital_h_, kExpUnitBits,
                          internal_params::kRandomBits3072, ch_table_.get());
}

std::string PublicKey::ToString() const {
  return fmt::format(
      "OU public key: n={}[{}bits], G={}[{}bits], H={}[{}bits], "
      "max_plaintext={}[~{}bits]",
      n_.ToHexString(), n_.BitCount(), capital_g_.ToHexString(),
      capital_g_.BitCount(), capital_h_.ToHexString(), capital_h_.BitCount(),
      PlaintextBound().ToHexString(), PlaintextBound().BitCount() - 1);
}

}  // namespace heu::lib::algorithms::ou
