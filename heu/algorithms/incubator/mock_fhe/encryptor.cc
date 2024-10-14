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

#include "heu/algorithms/incubator/mock_fhe/encryptor.h"

#include <string>

#include "fmt/ranges.h"

namespace heu::algos::mock_fhe {

Encryptor::Encryptor(size_t poly_degree, const std::shared_ptr<PublicKey> &pk)
    : poly_degree_(poly_degree), pk_(pk) {}

Ciphertext Encryptor::EncryptZeroT() const {
  return Ciphertext{std::vector<int64_t>(poly_degree_, 0)};
}

Ciphertext Encryptor::Encrypt(const Plaintext &m) const {
  YACL_ENFORCE(m->size() == poly_degree_, "illegal plaintext with degree {}",
               poly_degree_);
  return Ciphertext{m.array_, m.scale_};
}

Ciphertext Encryptor::SemiEncrypt(const Plaintext &plaintext) const {
  return Encrypt(plaintext);
}

void Encryptor::Encrypt(const Plaintext &m, Ciphertext *out) const {
  YACL_ENFORCE(m->size() == poly_degree_, "illegal plaintext with degree {}",
               poly_degree_);
  out->array_ = m.array_;
  out->scale_ = m.scale_;
}

void Encryptor::EncryptWithAudit(const Plaintext &m, Ciphertext *ct_out,
                                 std::string *audit_out) const {
  YACL_ENFORCE(m->size() == poly_degree_, "illegal plaintext with degree {}",
               poly_degree_);
  ct_out->array_ = m.array_;
  ct_out->scale_ = m.scale_;
  audit_out->assign(fmt::format("mock_fhe:{}", fmt::join(m.array_, ",")));
}

}  // namespace heu::algos::mock_fhe
