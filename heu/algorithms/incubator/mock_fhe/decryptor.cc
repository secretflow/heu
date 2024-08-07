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

#include "heu/algorithms/incubator/mock_fhe/decryptor.h"

namespace heu::algos::mock_fhe {

Decryptor::Decryptor(const std::shared_ptr<PublicKey> &pk,
                     const std::shared_ptr<SecretKey> &sk)
    : pk_(pk), sk_(sk) {}

void Decryptor::Decrypt(const Ciphertext &ct, Plaintext *out) const {
  out->array_ = ct.array_;
  out->scale_ = ct.scale_;
}

Plaintext Decryptor::Decrypt(const Ciphertext &ct) const {
  return Plaintext(ct.array_, ct.scale_);
}

}  // namespace heu::algos::mock_fhe
