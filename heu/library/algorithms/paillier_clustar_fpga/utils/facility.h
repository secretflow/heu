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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "heu/library/algorithms/paillier_clustar_fpga/ciphertext.h"
#include "heu/library/algorithms/paillier_clustar_fpga/plaintext.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

class CMonoFacility {
 public:
  CMonoFacility() = default;
  ~CMonoFacility() = default;

  static void CipherHeuToFpga(ConstSpan<Ciphertext> input_span,
                              const unsigned cipher_byte,
                              const std::shared_ptr<char>& pen,
                              const std::shared_ptr<char>& base,
                              const std::shared_ptr<char>& exp);

  static void CipherFpgaToHeu(const std::shared_ptr<char>& pen,
                              const std::shared_ptr<char>& exp, size_t size,
                              const unsigned cipher_byte,
                              std::vector<Ciphertext>& result);

  static void CipherVecToFpga(const std::vector<Ciphertext>& input_vec,
                              const unsigned cipher_byte,
                              const std::shared_ptr<char>& pen,
                              const std::shared_ptr<char>& base,
                              const std::shared_ptr<char>& exp);

  static void PlainHeuToFpga(ConstSpan<Plaintext> input_span,
                             const std::shared_ptr<int64_t[]>& pt_arr);

  static void PlainFpgaToHeu(const std::shared_ptr<char>& res_sptr,
                             size_t res_size, std::vector<Plaintext>& res_vec);

  static void FpgaEncode(char* pub_key_n, size_t pt_size,
                         const unsigned plain_bits,
                         const std::shared_ptr<int64_t[]>& pt_arr,
                         const std::shared_ptr<char>& res_fpn,
                         const std::shared_ptr<char>& res_base_fpn,
                         const std::shared_ptr<char>& res_exp_fpn);

  template <typename T>
  static void ValueVecToPtrVec(std::vector<T>& value_vec,
                               std::vector<T*>& ptr_vec);

  static std::string CharToString(char* input_str, size_t size);
};

template <typename T>
void CMonoFacility::ValueVecToPtrVec(std::vector<T>& value_vec,
                                     std::vector<T*>& ptr_vec) {
  size_t size = value_vec.size();
  for (size_t i = 0; i < size; i++) {
    ptr_vec.push_back(&value_vec[i]);
  }
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
