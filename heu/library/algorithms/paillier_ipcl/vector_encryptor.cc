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

#include "ipcl/plaintext.hpp"
#include "ipcl/ciphertext.hpp"
#include "heu/library/algorithms/paillier_ipcl/vector_encryptor.h"
#include "heu/library/algorithms/paillier_ipcl/utils.h"

namespace heu::lib::algorithms::paillier_ipcl {

Encryptor::Encryptor(const PublicKey& pk) {
  pk_ = pk.ipcl_pubkey_;
}

std::vector<Ciphertext> Encryptor::EncryptZero(int64_t size) const {
  std::vector<BigNumber> bn_zeros(size, BigNumber::Zero());
  ipcl::PlainText pt_zeros(bn_zeros);
  ipcl::CipherText ct_zeros = pk_.encrypt(pt_zeros);
  return ipcl_to_heu<Ciphertext, ipcl::CipherText>(ct_zeros);
}

// TODO: compute in parallel by 8 elements
std::vector<Ciphertext> Encryptor::Encrypt(ConstSpan<Plaintext> pts) const {
  std::vector<BigNumber> bn_vec;
  for (auto item : pts) {
    bn_vec.push_back(item->bn_);
  }
  ipcl::PlainText ipcl_pt(bn_vec);
  ipcl::CipherText ipcl_ct = pk_.encrypt(ipcl_pt);
  std::vector<Ciphertext> result;
  std::size_t ct_size = ipcl_ct.getSize();
  for (std::size_t i = 0; i < ct_size; i++) {
    result.push_back(Ciphertext(ipcl_ct[i]));
  }
  return result;
}

std::pair<std::vector<Ciphertext>, std::vector<std::string>> Encryptor::EncryptWithAudit(
    ConstSpan<Plaintext> pts) const {
  throw std::runtime_error("Not Implemented.");
}
}  // namespace heu::lib::algorithms::paillier_ipcl
