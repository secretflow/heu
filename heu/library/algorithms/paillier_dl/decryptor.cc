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

#include "heu/library/algorithms/paillier_dl/decryptor.h"
#include "heu/library/algorithms/util/he_assert.h"
#include "cgbn_wrapper/cgbn_wrapper.h"

namespace heu::lib::algorithms::paillier_dl {

#define VALIDATE(ct)                                          \
  HE_ASSERT(!(ct).c_.IsNegative() && (ct).c_ < pk_.n_square_, \
            "Decryptor: Invalid ciphertext")

void Decryptor::Decrypt(const std::vector<Ciphertext>& in_cts, std::vector<Plaintext>& out_pts) const {
  CGBNWrapper::Decrypt(in_cts, sk_, pk_, out_pts);
  for (int i=0; i<out_pts.size(); i++) {
    if (out_pts[i] >= pk_.half_n_) {
      out_pts[i] -= pk_.n_;
    }
  }
}

std::vector<Plaintext> Decryptor::Decrypt(const std::vector<Ciphertext>& cts) const {
  std::vector<Plaintext> tmp;
  Decrypt(cts, tmp);
  return tmp;
}

}  // namespace heu::lib::algorithms::paillier_dl
