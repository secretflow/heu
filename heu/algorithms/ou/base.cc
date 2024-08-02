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

#include "heu/algorithms/ou/base.h"

namespace heu::algos::ou {

namespace {
size_t kExpUnitBits = 10;
}  // namespace

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

Plaintext ItemTool::Clone(const Plaintext &pt) const { return pt; }

Ciphertext ItemTool::Clone(const Ciphertext &ct) const {
  return Ciphertext(ct.c_);
}

size_t ItemTool::Serialize(const Plaintext &pt, uint8_t *buf,
                           size_t buf_len) const {
  return pt.Serialize(buf, buf_len);
}

size_t ItemTool::Serialize(const Ciphertext &ct, uint8_t *buf,
                           size_t buf_len) const {
  return ct.c_.Serialize(buf, buf_len);
}

Plaintext ItemTool::DeserializePT(yacl::ByteContainerView buffer) const {
  Plaintext pt;
  pt.Deserialize(buffer);
  return pt;
}

Ciphertext ItemTool::DeserializeCT(yacl::ByteContainerView buffer) const {
  Ciphertext ct;
  ct.c_.Deserialize(buffer);
  return ct;
}

}  // namespace heu::algos::ou
