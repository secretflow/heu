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

#include "heu/library/algorithms/paillier_clustar_fpga/vector_encryptor.h"

#include <cmath>
#include <iomanip>
#include <sstream>
#include <vector>

#include "fmt/compile.h"
#include "fmt/format.h"

#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/paillier_operators.h"
#include "heu/library/algorithms/paillier_clustar_fpga/utils/facility.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

using fpga_engine::CFPGATypes;

// class Encryptor start
Encryptor::Encryptor(const PublicKey &pk)
    : pub_key_(pk),
      pub_key_helper_(&pub_key_),
      key_conf_(pub_key_.GetN().BitCount()) {
  pub_key_helper_.TransformToBytes();
}

std::vector<Ciphertext> Encryptor::EncryptZero(int64_t size) const {
  std::shared_ptr<char> obf_seeds = GenRandom(size);
  char *obf_seeds_ptr = obf_seeds.get();
  std::vector<Ciphertext> res;
  res.reserve(size);
  for (int64_t i = 0; i < size; i++) {
    Ciphertext zero_cipher(key_conf_.key_len_);
    memcpy(zero_cipher.GetMantissa(),
           obf_seeds_ptr + i * key_conf_.cipher_byte_, key_conf_.cipher_byte_);
    res.emplace_back(std::move(zero_cipher));
  }
  return res;
}

// Only support integer
std::vector<Ciphertext> Encryptor::Encrypt(ConstSpan<Plaintext> pts) const {
  return EncryptImpl(pts, nullptr);
}

std::vector<Ciphertext> Encryptor::EncryptImpl(
    ConstSpan<Plaintext> pts, std::vector<std::string> *audit_vec) const {
  // Part 0 Validity check
  int idx = 0;
  for (auto item : pts) {
    YACL_ENFORCE(
        item->CompareAbs(pub_key_.PlaintextBound()) < 0,
        "{} th msg number out of range, msg in hex={}, max in dec(abs)={}", idx,
        item->ToHexString(), pub_key_.PlaintextBound());
    idx++;
  }

  // Part 1 Encode
  size_t pts_size = pts.size();
  auto lambda_deleter = [](char *ptr) { free(ptr); };
  std::shared_ptr<char> res_fpn(
      fpga_engine::c_malloc_init_zero(key_conf_.plain_byte_ * pts_size),
      lambda_deleter);
  std::shared_ptr<char> res_base_fpn(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size),
      lambda_deleter);
  std::shared_ptr<char> res_exp_fpn(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size),
      lambda_deleter);

  Encode(pts, res_fpn, res_base_fpn, res_exp_fpn);

  // Part 2 encrypt
  // 2-1 encrypt without obfuscation
  std::shared_ptr<char> res_pen(
      fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * pts_size),
      lambda_deleter);
  std::shared_ptr<char> res_base_pen(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size),
      lambda_deleter);
  std::shared_ptr<char> res_exp_pen(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size),
      lambda_deleter);
  char *pub_key_n = pub_key_helper_.GetBytesN();
  char *pub_key_nsquare = pub_key_helper_.GetBytesNSquare();
  size_t fpga_dev_num = 0;  // no effect
  fpga_engine::encrypt_without_obf(
      res_fpn.get(), res_base_fpn.get(), res_exp_fpn.get(), res_pen.get(),
      res_base_pen.get(), res_exp_pen.get(), pub_key_n, nullptr,
      pub_key_nsquare, nullptr, key_conf_.plain_bits_, key_conf_.cipher_bits_,
      pts_size, fpga_dev_num);

  // release memory in time: encoded data
  res_fpn.reset();
  res_base_fpn.reset();
  res_exp_fpn.reset();

  // 2-2 add obfuscation to encrpted results
  std::shared_ptr<char> obf_seeds = GenRandom(pts_size);
  std::shared_ptr<char> obf_pen(
      fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * pts_size),
      lambda_deleter);
  std::shared_ptr<char> obf_base(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size),
      lambda_deleter);
  std::shared_ptr<char> obf_exp(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size),
      lambda_deleter);
  fpga_engine::obf_modular_multiplication(
      res_pen.get(), res_base_pen.get(), res_exp_pen.get(), obf_seeds.get(),
      obf_pen.get(), obf_base.get(), obf_exp.get(), nullptr, nullptr,
      pub_key_nsquare, nullptr, key_conf_.cipher_bits_, key_conf_.cipher_bits_,
      pts_size, fpga_dev_num);

  // release memory in time: initial encrypted data and obf
  res_pen.reset();
  res_base_pen.reset();
  res_exp_pen.reset();

  // Part 3 transform to heu type
  std::vector<Ciphertext> res_vec;
  res_vec.reserve(pts_size);
  CMonoFacility::CipherFpgaToHeu(obf_pen, obf_exp, pts_size,
                                 key_conf_.cipher_byte_, res_vec);

  // Part 4 handle autit case
  char *obf_seeds_ptr = obf_seeds.get();
  if (audit_vec != nullptr) {
    for (size_t i = 0; i < pts_size; i++) {
      std::string audit_str =
          fmt::format(FMT_COMPILE("p:{},rn:{},c:{}"), pts[i]->ToHexString(),
                      CMonoFacility::CharToString(
                          obf_seeds_ptr + i * key_conf_.cipher_bits_,
                          key_conf_.cipher_bits_),
                      res_vec[i].ToString());
      audit_vec->emplace_back(std::move(audit_str));
    }
  }
  obf_seeds.reset();

  return res_vec;
}

std::pair<std::vector<Ciphertext>, std::vector<std::string>>
Encryptor::EncryptWithAudit(ConstSpan<Plaintext> pts) const {
  std::vector<std::string> audit;
  audit.reserve(pts.size());
  auto cipher_vec = EncryptImpl(pts, &audit);
  return {std::move(cipher_vec), std::move(audit)};
}

std::shared_ptr<char> Encryptor::GenRandom(size_t count) const {
  auto lambda_deleter = [](char *ptr) { free(ptr); };
  std::shared_ptr<char> res_rand(
      fpga_engine::c_malloc_init_zero(key_conf_.encr_random_byte_ * count),
      lambda_deleter);
  fpga_engine::mpint_random(res_rand.get(), key_conf_.encr_random_bit_len_,
                            count, pub_key_helper_.GetBytesN());

  size_t fpga_dev_num = 0;  // no effect
  std::shared_ptr<char> res_data(
      fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * count),
      lambda_deleter);
  fpga_engine::obf_modular_exponentiation(
      res_rand.get(), key_conf_.encr_random_bit_len_,
      pub_key_helper_.GetBytesN(), nullptr, pub_key_helper_.GetBytesNSquare(),
      nullptr, res_data.get(), key_conf_.cipher_bits_, count, fpga_dev_num);
  return res_data;
}

void Encryptor::Encode(ConstSpan<Plaintext> pts, std::shared_ptr<char> &res_fpn,
                       std::shared_ptr<char> &res_base_fpn,
                       std::shared_ptr<char> &res_exp_fpn) const {
  size_t pts_size = pts.size();
  std::shared_ptr<int64_t[]> pt_arr(new int64_t[pts_size]);

  CMonoFacility::PlainHeuToFpga(pts, pt_arr);

  char *pub_key_n = pub_key_helper_.GetBytesN();
  CMonoFacility::FpgaEncode(pub_key_n, pts_size, key_conf_.plain_bits_, pt_arr,
                            res_fpn, res_base_fpn, res_exp_fpn);
}

std::vector<Ciphertext> Encryptor::EncryptWithoutObf(
    ConstSpan<Plaintext> pts) const {
  // Part 1 Encode
  size_t pts_size = pts.size();
  auto lambda_deleter = [](char *ptr) { free(ptr); };
  std::shared_ptr<char> res_fpn(
      fpga_engine::c_malloc_init_zero(key_conf_.plain_byte_ * pts_size),
      lambda_deleter);
  std::shared_ptr<char> res_base_fpn(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size),
      lambda_deleter);
  std::shared_ptr<char> res_exp_fpn(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size),
      lambda_deleter);

  Encode(pts, res_fpn, res_base_fpn, res_exp_fpn);

  // Part 2 encrypt
  // 2-1 encrypt without obfuscation
  std::shared_ptr<char> res_pen(
      fpga_engine::c_malloc_init_zero(key_conf_.cipher_byte_ * pts_size),
      lambda_deleter);
  std::shared_ptr<char> res_base_pen(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size),
      lambda_deleter);
  std::shared_ptr<char> res_exp_pen(
      fpga_engine::c_malloc_init_zero(CFPGATypes::U_INT32_BYTE * pts_size),
      lambda_deleter);
  char *pub_key_n = pub_key_helper_.GetBytesN();
  char *pub_key_nsquare = pub_key_helper_.GetBytesNSquare();
  size_t fpga_dev_num = 0;  // no effect
  fpga_engine::encrypt_without_obf(
      res_fpn.get(), res_base_fpn.get(), res_exp_fpn.get(), res_pen.get(),
      res_base_pen.get(), res_exp_pen.get(), pub_key_n, nullptr,
      pub_key_nsquare, nullptr, key_conf_.plain_bits_, key_conf_.cipher_bits_,
      pts_size, fpga_dev_num);

  // release memory in time: encoded data
  res_fpn.reset();
  res_base_fpn.reset();
  res_exp_fpn.reset();

  // Part 3 transform to heu type
  std::vector<Ciphertext> res_vec;
  res_vec.reserve(pts_size);
  CMonoFacility::CipherFpgaToHeu(res_pen, res_exp_pen, pts_size,
                                 key_conf_.cipher_byte_, res_vec);

  return res_vec;
}

// class Encryptor end

}  // namespace heu::lib::algorithms::paillier_clustar_fpga
