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

#include "heu/library/algorithms/paillier_zahlen/decryptor.h"
#include "heu/library/algorithms/util/he_assert.h"
#include "cgbn_wrapper/cgbn_wrapper.h"

namespace heu::lib::algorithms::paillier_z {

#define VALIDATE(ct)                                          \
  HE_ASSERT(!(ct).c_.IsNegative() && (ct).c_ < pk_.n_square_, \
            "Decryptor: Invalid ciphertext")

void Decryptor::Decrypt(const Ciphertext& ct, MPInt* out) const {
  // VALIDATE(ct);
  CGBNWrapper::Decrypt(ct, sk_, pk_, out);
}

void Decryptor::Decrypt(absl::Span<const Ciphertext>& in_cts, absl::Span<Plaintext> *out_pts) const {
  CGBNWrapper::Decrypt(in_cts, sk_, pk_, out_pts);
}

MPInt Decryptor::Decrypt(const Ciphertext& ct) const {
  MPInt mp;
  Decrypt(ct, &mp);
  return mp;
}

std::vector<Plaintext> Decryptor::Decrypt(absl::Span<const Ciphertext>& cts) const {
  std::vector<Plaintext> tmp;
  absl::Span<Plaintext> tmp_span = absl::Span<Plaintext>(tmp);
  Decrypt(cts, &tmp_span);
  return tmp;
}

}  // namespace heu::lib::algorithms::paillier_z
