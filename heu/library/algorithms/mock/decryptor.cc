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

#include "heu/library/algorithms/mock/decryptor.h"

namespace heu::lib::algorithms::mock {

#ifdef IMPL_SCALAR_SPI
void Decryptor::Decrypt(const Ciphertext &ct, Plaintext *out) const {
  out->Set(ct.bn_);
}

Plaintext Decryptor::Decrypt(const Ciphertext &ct) const {
  Plaintext pt;
  pt.Set(ct.bn_);
  return pt;
}
#endif

#ifdef IMPL_VECTORIZED_SPI
std::vector<Plaintext> Decryptor::Decrypt(ConstSpan<Ciphertext> cts) const {
  std::vector<Plaintext> res;
  res.reserve(cts.size());
  for (const auto &ct : cts) {
    res.emplace_back(ct->bn_);
  }
  return res;
}

void Decryptor::Decrypt(ConstSpan<Ciphertext> in_cts,
                        Span<Plaintext> out_pts) const {
  for (size_t i = 0; i < in_cts.size(); ++i) {
    out_pts[i]->Set(in_cts[i]->bn_);
  }
}
#endif

}  // namespace heu::lib::algorithms::mock
