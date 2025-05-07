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
  YACL_ENFORCE(density > 0, "density must > 0");
  kExpUnitBits = density;
}

void PublicKey::Init() {
  n_square_ = n_ * n_;
  n_half_ = n_ >> 1;
  key_size_ = n_.BitCount();

  m_space_ = BigInt::CreateMontgomerySpace(n_square_);
  hs_table_ = std::make_shared<BaseTable>();
  size_t word_size = m_space_->GetWordBitSize();
  m_space_->MakeBaseTable(
      h_s_, kExpUnitBits,
      // make max_exp_bits divisible by word_size
      (key_size_ / 2 + word_size - 1) / word_size * word_size, hs_table_.get());
}

std::string PublicKey::ToString() const {
  return fmt::format(
      "Z-paillier PK: n={}[{}bits], h_s={}, max_plaintext={}[~{}bits]",
      n_.ToHexString(), n_.BitCount(), h_s_.ToHexString(),
      PlaintextBound().ToHexString(), PlaintextBound().BitCount());
}
}  // namespace heu::lib::algorithms::paillier_z
