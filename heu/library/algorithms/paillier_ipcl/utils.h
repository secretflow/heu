// Copyright 2022 Ant Group Co., Ltd.
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

#include "ipcl/bignum.h"
#include "ipcl/plaintext.hpp"
#include "ipcl/ciphertext.hpp"
#include "heu/library/algorithms/paillier_ipcl/ciphertext.h"
#include "heu/library/algorithms/paillier_ipcl/public_key.h"

namespace heu::lib::algorithms::paillier_ipcl {

// HI_BIT_SET is base/2
// Assumes CHAR_BIT == 8
const auto HI_BIT_SET = uint32_t(1) << (sizeof(uint32_t) * 8 - 1);  

int compare(const std::vector<uint32_t>& a, const std::vector<uint32_t>& b);
bool is_zero(std::vector<uint32_t>& value);
void clamp(std::vector<uint32_t>& bn);
void subfrom(std::vector<uint32_t>& a, const std::vector<uint32_t>& b);
void shift_right_one(std::vector<uint32_t>& bn);
void shift_left_one(std::vector<uint32_t>& bn);
void set_bit_at(std::vector<uint32_t>& bn, std::size_t index, bool set=true);
std::vector<uint32_t> divide(std::vector<uint32_t>& n, std::vector<uint32_t> d);
std::string to_string(const BigNumber& bn);
ipcl::CipherText to_ipcl_ciphertext(const PublicKey& pk, ConstSpan<Ciphertext> ct);
ipcl::PlainText to_ipcl_plaintext(ConstSpan<Plaintext> pt);

template <typename T1, typename T2>
std::vector<T1> ipcl_to_heu(const T2& value) {
  if ((std::is_same<T1, Plaintext>::value && std::is_same<T2, ipcl::PlainText>::value)
      || (std::is_same<T1, Ciphertext>::value && std::is_same<T2, ipcl::CipherText>::value)) {
    std::vector<BigNumber> bn_data = value.getTexts();
    size_t bn_size = value.getSize();
    std::vector<T1> result;
    for (size_t i = 0; i < bn_size; i++) {
      result.push_back(T1(bn_data[i]));
    }
    return result;
  } else {
    throw(std::runtime_error("ipcl_to_heu: data type mismatch."));
  }
}

template <typename T>
void value_vec_to_pts_vec(std::vector<T>& value_vec, std::vector<T*>& pts_vec) {
  int size = value_vec.size();
  for (int i = 0; i < size; i++) {
    pts_vec.push_back(&value_vec[i]);
  }
}

}
