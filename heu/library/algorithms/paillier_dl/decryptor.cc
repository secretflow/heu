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
#include "heu/library/algorithms/paillier_dl/cgbn_wrapper/cgbn_wrapper.h"
#include "heu/library/algorithms/paillier_dl/utils.h"

namespace heu::lib::algorithms::paillier_dl {

#define VALIDATE(ct)                                          \
  HE_ASSERT(!(ct).c_.IsNegative() && (ct).c_ < pk_.n_square_, \
            "Decryptor: Invalid ciphertext")

std::vector<Plaintext> Decryptor::DecryptImplVector(const std::vector<Ciphertext>& in_cts) const {
  std::vector<Plaintext> out_pts(in_cts.size()); 
  CGBNWrapper::Decrypt(in_cts, sk_, pk_, out_pts);
  for (int i=0; i<out_pts.size(); ++i) {
    if (out_pts[i] >= pk_.half_n_) {
      out_pts[i] -= pk_.n_;
    }
  }
  return out_pts;
}

void Decryptor::Decrypt(ConstSpan<Ciphertext> in_cts, Span<Plaintext> out_pts) const {
  std::vector<Ciphertext> in_cts_vec;
  for (int i=0; i<in_cts.size(); ++i) {
    in_cts_vec.push_back(*in_cts[i]);
  }
  auto out_pts_vec = DecryptImplVector(in_cts_vec);
  std::vector<Plaintext *> out_pts_pt;
  ValueVecToPtsVec(out_pts_vec, out_pts_pt);
  out_pts = absl::MakeSpan(out_pts_pt.data(), out_pts_vec.size());
}

std::vector<Plaintext> Decryptor::Decrypt(ConstSpan<Ciphertext> in_cts) const {
  std::vector<Ciphertext> in_cts_vec;
  for (int i=0; i<in_cts.size(); ++i) {
    in_cts_vec.push_back(*in_cts[i]);
  }
  auto out_pts_vec = DecryptImplVector(in_cts_vec);
  return out_pts_vec;
}

}  // namespace heu::lib::algorithms::paillier_dl
