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

#include "heu/library/algorithms/paillier_clustar_fpga/utils/facility.h"

#include <iomanip>
#include <iostream>
#include <sstream>

#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/paillier_operators.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

void CMonoFacility::CipherHeuToFpga(ConstSpan<Ciphertext> input_span,
                                    const unsigned cipher_byte,
                                    const std::shared_ptr<char>& pen,
                                    const std::shared_ptr<char>& base,
                                    const std::shared_ptr<char>& exp) {
  char* pen_ptr = pen.get();
  char* base_ptr = base.get();
  char* exp_ptr = exp.get();
  unsigned cipher_base = CFPGATypes::CIPHER_BASE;
  size_t i = 0;
  for (auto item : input_span) {
    memcpy(pen_ptr + i * cipher_byte, item->GetMantissa(), cipher_byte);
    memcpy(base_ptr + i * CFPGATypes::U_INT32_BYTE, &cipher_base,
           CFPGATypes::U_INT32_BYTE);
    int cur_exp = item->GetExp();
    memcpy(exp_ptr + i * CFPGATypes::U_INT32_BYTE, &cur_exp,
           CFPGATypes::U_INT32_BYTE);
    i++;
  }
}

void CMonoFacility::CipherFpgaToHeu(const std::shared_ptr<char>& pen,
                                    const std::shared_ptr<char>& exp,
                                    size_t size, const unsigned cipher_byte,
                                    std::vector<Ciphertext>& result) {
  char* pen_ptr = pen.get();
  char* exp_ptr = exp.get();
  for (size_t i = 0; i < size; i++) {
    Ciphertext cur_cipher(cipher_byte);
    memcpy(cur_cipher.GetMantissa(), pen_ptr + i * cipher_byte, cipher_byte);
    int cur_exp = 0;
    memcpy(&cur_exp, exp_ptr + i * CFPGATypes::U_INT32_BYTE,
           CFPGATypes::U_INT32_BYTE);
    cur_cipher.SetExp(cur_exp);

    result.emplace_back(std::move(cur_cipher));  //
  }
}

void CMonoFacility::CipherVecToFpga(const std::vector<Ciphertext>& input_vec,
                                    const unsigned cipher_byte,
                                    const std::shared_ptr<char>& pen,
                                    const std::shared_ptr<char>& base,
                                    const std::shared_ptr<char>& exp) {
  char* pen_ptr = pen.get();
  char* base_ptr = base.get();
  char* exp_ptr = exp.get();
  unsigned cipher_base = CFPGATypes::CIPHER_BASE;
  size_t i = 0;
  for (const Ciphertext& item : input_vec) {
    memcpy(pen_ptr + i * cipher_byte, item.GetMantissa(), cipher_byte);
    memcpy(base_ptr + i * CFPGATypes::U_INT32_BYTE, &cipher_base,
           CFPGATypes::U_INT32_BYTE);
    int cur_exp = item.GetExp();
    memcpy(exp_ptr + i * CFPGATypes::U_INT32_BYTE, &cur_exp,
           CFPGATypes::U_INT32_BYTE);
    i++;
  }
}

void CMonoFacility::PlainHeuToFpga(ConstSpan<Plaintext> input_span,
                                   const std::shared_ptr<int64_t[]>& pt_arr) {
  int cnt = 0;
  for (auto item : input_span) {
    int64_t item_val = item->Get<int64_t>();
    pt_arr[cnt++] = item_val;
  }
}

void CMonoFacility::PlainFpgaToHeu(const std::shared_ptr<char>& res_sptr,
                                   size_t res_size,
                                   std::vector<Plaintext>& res_vec) {
  char* result_ptr = res_sptr.get();
  for (size_t k = 0; k < res_size; k++) {
    // TODO: transform to int64_t, what if uint64_t?
    int64_t val = 0;
    memcpy(&val, result_ptr + k * CFPGATypes::INT64_BYTE,
           CFPGATypes::INT64_BYTE);
    Plaintext cur_plain_text;
    cur_plain_text.Set<int64_t>(val);
    res_vec.emplace_back(std::move(cur_plain_text));
  }
}

void CMonoFacility::FpgaEncode(char* pub_key_n, size_t pts_size,
                               const unsigned plain_bits,
                               const std::shared_ptr<int64_t[]>& pt_arr,
                               const std::shared_ptr<char>& res_fpn,
                               const std::shared_ptr<char>& res_base_fpn,
                               const std::shared_ptr<char>& res_exp_fpn) {
  int32_t precision = -1;   // hard code to -1 here
  size_t fpga_dev_num = 0;  // no effect
  fpga_engine::encode_int(pt_arr.get(), res_fpn.get(), res_base_fpn.get(),
                          res_exp_fpn.get(), precision, pub_key_n, nullptr,
                          plain_bits, pts_size, fpga_dev_num);
}

std::string CMonoFacility::CharToString(char* input_str, size_t size) {
  std::ostringstream ss;
  // from low to high
  for (int i = 0; i < static_cast<int>(size); i++) {
    ss << std::hex << std::setfill('0') << std::setw(2)
       << +static_cast<uint8_t>(*(input_str + i));
  }
  return ss.str();
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
