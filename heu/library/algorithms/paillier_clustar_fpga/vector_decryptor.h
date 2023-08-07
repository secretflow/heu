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
#include "heu/library/algorithms/paillier_clustar_fpga/secret_key.h"
#include "heu/library/algorithms/paillier_clustar_fpga/utils/pub_key_helper.h"
#include "heu/library/algorithms/paillier_clustar_fpga/utils/secr_key_helper.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

class Decryptor {
 public:
  explicit Decryptor(const PublicKey& pub_key, const SecretKey& pri_key);

  std::vector<Plaintext> Decrypt(ConstSpan<Ciphertext> cts) const;
  void Decrypt(ConstSpan<Ciphertext> in_cts, Span<Plaintext> out_pts) const;

  std::vector<Plaintext> Decode(std::shared_ptr<char>& res_fpn,
                                std::shared_ptr<char>& res_base,
                                std::shared_ptr<char>& res_exp,
                                size_t cts_size) const;

 private:
  PublicKey pub_key_;
  SecretKey pri_key_;
  CPubKeyHelper pub_key_helper_;
  CSecrKeyHelper secr_key_helper_;
  fpga_engine::CKeyLenConfig key_conf_;
};

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
