// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "heu/library/algorithms/paillier_ipcl/ciphertext.h"
#include "heu/library/algorithms/paillier_ipcl/plaintext.h"
#include "heu/library/algorithms/paillier_ipcl/public_key.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_ipcl {

class Evaluator {
 public:
  explicit Evaluator(const PublicKey &pk);

  void Randomize(Span<Ciphertext> ct) const;

  std::vector<Ciphertext> Add(ConstSpan<Ciphertext> a,
                              ConstSpan<Ciphertext> b) const;
  std::vector<Ciphertext> Add(ConstSpan<Ciphertext> a,
                              ConstSpan<Plaintext> b) const;
  std::vector<Ciphertext> Add(ConstSpan<Plaintext> a,
                              ConstSpan<Ciphertext> b) const;
  std::vector<Plaintext> Add(ConstSpan<Plaintext> a,
                             ConstSpan<Plaintext> b) const;

  void AddInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const;
  void AddInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const;
  void AddInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

  std::vector<Ciphertext> Sub(ConstSpan<Ciphertext> a,
                              ConstSpan<Ciphertext> b) const;
  std::vector<Ciphertext> Sub(ConstSpan<Ciphertext> a,
                              ConstSpan<Plaintext> b) const;
  std::vector<Ciphertext> Sub(ConstSpan<Plaintext> a,
                              ConstSpan<Ciphertext> b) const;
  std::vector<Plaintext> Sub(ConstSpan<Plaintext> a,
                             ConstSpan<Plaintext> b) const;

  void SubInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const;
  void SubInplace(Span<Ciphertext> a, ConstSpan<Plaintext> p) const;
  void SubInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

  std::vector<Ciphertext> Mul(ConstSpan<Ciphertext> a,
                              ConstSpan<Plaintext> b) const;
  std::vector<Ciphertext> Mul(ConstSpan<Plaintext> a,
                              ConstSpan<Ciphertext> b) const;
  std::vector<Plaintext> Mul(ConstSpan<Plaintext> a,
                             ConstSpan<Plaintext> b) const;

  void MulInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const;
  void MulInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

  // out = -a
  std::vector<Ciphertext> Negate(ConstSpan<Ciphertext> a) const;
  void NegateInplace(Span<Ciphertext> a) const;

  PublicKey pk_;
};

}  // namespace heu::lib::algorithms::paillier_ipcl
