// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "heu/library/algorithms/paillier_ipcl/vector_encryptor.h"

#include "ipcl/ciphertext.hpp"
#include "ipcl/plaintext.hpp"

#include "heu/library/algorithms/paillier_ipcl/utils.h"

namespace heu::lib::algorithms::paillier_ipcl {

Encryptor::Encryptor(const PublicKey& pk) {
  pk_ = pk.ipcl_pubkey_;
  pt_bound_ = pk.pt_bound_;
}

std::vector<Ciphertext> Encryptor::EncryptZero(int64_t size) const {
  std::vector<BigNumber> bn_zeros(size, BigNumber::Zero());
  ipcl::PlainText pt_zeros(bn_zeros);
  ipcl::CipherText ct_zeros = pk_.encrypt(pt_zeros);
  return IpclToHeu<Ciphertext, ipcl::CipherText>(ct_zeros);
}

// TODO: compute in parallel by 8 elements
std::vector<Ciphertext> Encryptor::Encrypt(ConstSpan<Plaintext> pts) const {
  std::vector<BigNumber> bn_vec;
  for (auto item : pts) {
    YACL_ENFORCE(Plaintext::Absolute(*item) < pt_bound_,
                 "Plaintext out of range");
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

std::pair<std::vector<Ciphertext>, std::vector<std::string>>
Encryptor::EncryptWithAudit(ConstSpan<Plaintext> pts) const {
  YACL_THROW("Not Implemented.");
}
}  // namespace heu::lib::algorithms::paillier_ipcl
