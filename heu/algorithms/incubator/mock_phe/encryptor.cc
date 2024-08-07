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

#include "heu/algorithms/incubator/mock_phe/encryptor.h"

#include <string>

namespace heu::algos::mock_phe {

Ciphertext Encryptor::EncryptZeroT() const { return Ciphertext{0_mp}; }

Ciphertext Encryptor::Encrypt(const Plaintext &m) const {
  YACL_ENFORCE(
      m.BitCount() <= pk_->KeySize(),
      "Plaintext {} is too large, cannot encrypt. m_bits={}, key_size={}",
      m.ToHexString(), m.BitCount(), pk_->KeySize());
  return Ciphertext{m};
}

void Encryptor::Encrypt(const Plaintext &m, Ciphertext *out) const {
  YACL_ENFORCE(
      m.BitCount() <= pk_->KeySize(),
      "Plaintext {} is too large, cannot encrypt. m_bits={}, key_size={}",
      m.ToHexString(), m.BitCount(), pk_->KeySize());
  out->bn_ = m;
}

void Encryptor::EncryptWithAudit(const Plaintext &m, Ciphertext *ct_out,
                                 std::string *audit_out) const {
  YACL_ENFORCE(
      m.BitCount() <= pk_->KeySize(),
      "Plaintext {} is too large, cannot encrypt. m_bits={}, key_size={}",
      m.ToHexString(), m.BitCount(), pk_->KeySize());

  ct_out->bn_ = m;
  audit_out->assign(fmt::format("mock_phe:{}", ct_out->bn_.ToString()));
}

}  // namespace heu::algos::mock_phe
