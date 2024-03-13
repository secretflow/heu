// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ipcl/pub_key.hpp"

#include "heu/library/algorithms/paillier_ipcl/ciphertext.h"
#include "heu/library/algorithms/paillier_ipcl/plaintext.h"
#include "heu/library/algorithms/paillier_ipcl/public_key.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_ipcl {

class Encryptor {
 public:
  explicit Encryptor(const PublicKey &pk);

  std::vector<Ciphertext> EncryptZero(int64_t size) const;
  std::vector<Ciphertext> Encrypt(ConstSpan<Plaintext> pts) const;

  std::pair<std::vector<Ciphertext>, std::vector<std::string>> EncryptWithAudit(
      ConstSpan<Plaintext> pts) const;

 private:
  ipcl::PublicKey pk_;
  Plaintext pt_bound_;
};

}  // namespace heu::lib::algorithms::paillier_ipcl
