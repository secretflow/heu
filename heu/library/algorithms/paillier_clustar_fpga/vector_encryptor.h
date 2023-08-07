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

#include "heu/library/algorithms/paillier_clustar_fpga/ciphertext.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"
#include "heu/library/algorithms/paillier_clustar_fpga/plaintext.h"
#include "heu/library/algorithms/paillier_clustar_fpga/public_key.h"
#include "heu/library/algorithms/paillier_clustar_fpga/utils/pub_key_helper.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

class Encryptor {
 public:
  Encryptor() = default;
  explicit Encryptor(const PublicKey& pk);
  ~Encryptor() = default;

  std::vector<Ciphertext> EncryptZero(int64_t size) const;
  std::vector<Ciphertext> Encrypt(ConstSpan<Plaintext> pts) const;
  std::vector<Ciphertext> EncryptWithoutObf(ConstSpan<Plaintext> pts) const;

  std::pair<std::vector<Ciphertext>, std::vector<std::string>> EncryptWithAudit(
      ConstSpan<Plaintext> pts) const;

  void Encode(ConstSpan<Plaintext> pts, std::shared_ptr<char>& res_fpn,
              std::shared_ptr<char>& res_base_fpn,
              std::shared_ptr<char>& res_exp_fpn) const;

 private:
  std::shared_ptr<char> GenRandom(size_t count) const;
  std::vector<Ciphertext> EncryptImpl(
      ConstSpan<Plaintext> pts, std::vector<std::string>* audit_vec) const;

 private:
  PublicKey pub_key_;
  CPubKeyHelper pub_key_helper_;
  fpga_engine::CKeyLenConfig key_conf_;
};

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
