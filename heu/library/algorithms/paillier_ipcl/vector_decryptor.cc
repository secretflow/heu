// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "heu/library/algorithms/paillier_ipcl/vector_decryptor.h"

namespace heu::lib::algorithms::paillier_ipcl {

Decryptor::Decryptor(const PublicKey &pk, const SecretKey &sk) {
  pk_ = pk.ipcl_pubkey_;
  sk_ = sk.ipcl_prikey_;
  half_n_.bn_ = *pk_.getN() / 2;
}

std::vector<Plaintext> Decryptor::Decrypt(ConstSpan<Ciphertext> cts) const {
  std::vector<BigNumber> ct_vec;
  ct_vec.reserve(cts.size());
  for (auto item : cts) {
    ct_vec.push_back(item->bn_);
  }
  ipcl::CipherText input(pk_, ct_vec);
  std::vector<BigNumber> ipcl_res = sk_.decrypt(input);
  std::vector<Plaintext> pt_vec;
  auto n = *pk_.getN();
  for (auto item : ipcl_res) {
    // handle negative numbers
    if (item > half_n_.bn_) {
      item -= n;
    }
    pt_vec.push_back(Plaintext(item));
  }
  return pt_vec;
}

void Decryptor::Decrypt(ConstSpan<Ciphertext> in_cts,
                        Span<Plaintext> out_pts) const {
  std::vector<BigNumber> ct_vec;
  for (auto item : in_cts) {
    ct_vec.push_back(item->bn_);
  }
  ipcl::CipherText input(pk_, ct_vec);
  std::vector<BigNumber> ipcl_res = sk_.decrypt(input);
  auto n = *pk_.getN();
  auto half_n = n / 2;
  size_t size = ipcl_res.size();
  for (size_t i = 0; i < size; i++) {
    // handle negative numbers
    if (ipcl_res[i] > half_n) {
      ipcl_res[i] -= n;
    }
    *out_pts[i] = Plaintext(ipcl_res[i]);
  }
}
}  // namespace heu::lib::algorithms::paillier_ipcl
