// Copyright 2023 Clustar Technology Co., Ltd.
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

#pragma once

#include <memory>
#include <vector>

#include "heu/library/algorithms/paillier_clustar_fpga/ciphertext.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"
#include "heu/library/algorithms/paillier_clustar_fpga/plaintext.h"
#include "heu/library/algorithms/paillier_clustar_fpga/public_key.h"
#include "heu/library/algorithms/paillier_clustar_fpga/utils/pub_key_helper.h"
#include "heu/library/algorithms/paillier_clustar_fpga/vector_encryptor.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

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

  // Sum
  // Add cipher input to sum
  Ciphertext ReduceSum(ConstSpan<Ciphertext> input) const;
  // Add plain input to sum
  Plaintext ReduceSum(ConstSpan<Plaintext> input) const;

 private:
  PublicKey pub_key_;
  Encryptor encryptor_;
  CPubKeyHelper pub_key_helper_;
  fpga_engine::CKeyLenConfig key_conf_;
};

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
