// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ipcl/pri_key.hpp"

#include "heu/library/algorithms/paillier_ipcl/ciphertext.h"
#include "heu/library/algorithms/paillier_ipcl/plaintext.h"
#include "heu/library/algorithms/paillier_ipcl/public_key.h"
#include "heu/library/algorithms/paillier_ipcl/secret_key.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_ipcl {

class Decryptor {
 public:
  explicit Decryptor(const PublicKey& _, const SecretKey& sk);

  std::vector<Plaintext> Decrypt(ConstSpan<Ciphertext> cts) const;
  void Decrypt(ConstSpan<Ciphertext> in_cts, Span<Plaintext> out_pts) const;

 private:
  ipcl::PrivateKey sk_;
  ipcl::PublicKey pk_;
  Plaintext half_n_;
};

}  // namespace heu::lib::algorithms::paillier_ipcl
