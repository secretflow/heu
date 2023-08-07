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

#include "heu/library/algorithms/paillier_clustar_fpga/vector_decryptor.h"

#include <iomanip>
#include <sstream>

#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/paillier_operators.h"
#include "heu/library/algorithms/paillier_clustar_fpga/utils/facility.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

Decryptor::Decryptor(const PublicKey &pub_key, const SecretKey &pri_key)
    : pub_key_(pub_key),
      pri_key_(pri_key),
      pub_key_helper_(&pub_key_),
      secr_key_helper_(&pri_key_, pub_key_.GetN().BitCount()),
      key_conf_(pub_key_.GetN().BitCount()) {
  pub_key_helper_.TransformToBytes();
  secr_key_helper_.TransformToBytes();
}

std::vector<Plaintext> Decryptor::Decrypt(ConstSpan<Ciphertext> cts) const {
  // Part 1 Transform heu to FPGA format
  size_t cts_size = cts.size();
  auto lambda_deleter = [](char *ptr) { free(ptr); };
  std::shared_ptr<char> src_pen(
      fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * cts_size),
      lambda_deleter);
  std::shared_ptr<char> src_base(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * cts_size),
      lambda_deleter);
  std::shared_ptr<char> src_exp(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * cts_size),
      lambda_deleter);
  unsigned cipher_base = CFPGATypes::CIPHER_BASE;
  size_t i = 0;
  char *src_pen_ptr = src_pen.get();
  char *src_base_ptr = src_base.get();
  char *src_exp_ptr = src_exp.get();
  for (auto item : cts) {
    memcpy(src_pen_ptr + i * key_conf_.cipher_byte_, item->GetMantissa(),
           key_conf_.cipher_byte_);

    memcpy(src_base_ptr + i * CFPGATypes::U_INT32_BYTE, &cipher_base,
           CFPGATypes::U_INT32_BYTE);

    int cur_exp = item->GetExp();
    memcpy(src_exp_ptr + i * CFPGATypes::U_INT32_BYTE, &cur_exp,
           CFPGATypes::U_INT32_BYTE);

    i++;
  }

  // Part 2 Decrypt
  std::shared_ptr<char> res_fpn(
      fpga_engine::c_malloc_init_zero(key_conf_.plain_byte_ * cts_size),
      lambda_deleter);
  std::shared_ptr<char> res_base(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * cts_size),
      lambda_deleter);
  std::shared_ptr<char> res_exp(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * cts_size),
      lambda_deleter);
  char *pub_key_n = pub_key_helper_.GetBytesN();
  char *pri_key_p = secr_key_helper_.GetBytesP();
  char *pri_key_q = secr_key_helper_.GetBytesQ();
  char *pri_key_p_square = secr_key_helper_.GetBytesPSquare();
  char *pri_key_q_square = secr_key_helper_.GetBytesQSquare();
  char *pri_key_q_inverse = secr_key_helper_.GetBytesQInverse();
  char *pri_key_hp = secr_key_helper_.GetBytesHP();
  char *pri_key_hq = secr_key_helper_.GetBytesHQ();
  size_t fpga_dev_num = 0;  // no effect
  fpga_engine::decrypt(src_pen.get(), src_base.get(), src_exp.get(),
                       res_fpn.get(), res_base.get(), res_exp.get(), pub_key_n,
                       nullptr, nullptr, nullptr, pri_key_p, pri_key_q,
                       pri_key_p_square, pri_key_q_square, pri_key_q_inverse,
                       pri_key_hp, pri_key_hq, key_conf_.plain_bits_,
                       key_conf_.cipher_bits_, cts_size, fpga_dev_num);
  // release memory in time: raw data
  src_pen.reset();
  src_base.reset();
  src_exp.reset();

  // Part 3 Decode
  return Decode(res_fpn, res_base, res_exp, cts_size);
}

void Decryptor::Decrypt(ConstSpan<Ciphertext> in_cts,
                        Span<Plaintext> out_pts) const {
  std::vector<Plaintext> res_vec = Decrypt(in_cts);
  size_t res_size = res_vec.size();
  for (size_t i = 0; i < res_size; i++) {
    *out_pts[i] = std::move(res_vec[i]);
  }
}

std::vector<Plaintext> Decryptor::Decode(std::shared_ptr<char> &res_fpn,
                                         std::shared_ptr<char> &res_base,
                                         std::shared_ptr<char> &res_exp,
                                         size_t cts_size) const {
  // 1 decode
  auto lambda_deleter = [](char *ptr) { free(ptr); };
  std::shared_ptr<char> res_sptr(
      fpga_engine::c_malloc_init_zero(CFPGATypes::INT64_BYTE * cts_size),
      lambda_deleter);
  char *pub_key_n = pub_key_helper_.GetBytesN();
  char *pub_key_max_int = pub_key_helper_.GetBytesMaxInt();
  fpga_engine::decode_int(res_fpn.get(), res_base.get(), res_exp.get(),
                          pub_key_n, pub_key_max_int, key_conf_.plain_bits_,
                          res_sptr.get(), cts_size);

  // 2 result format
  std::vector<Plaintext> res_vec;
  res_vec.reserve(cts_size);
  CMonoFacility::PlainFpgaToHeu(res_sptr, cts_size, res_vec);

  return res_vec;
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
