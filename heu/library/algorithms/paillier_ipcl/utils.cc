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

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include "utils.h"

namespace heu::lib::algorithms::paillier_ipcl {

// Compile a with b, returning 1:a>b, 0:a==b, -1:a<b
int compare(const std::vector<uint32_t>& a, const std::vector<uint32_t>& b) {
  const auto max_size = std::max(a.size(), b.size());
  for(auto i = max_size; i > 0; i--) {
    auto idx = i - 1;
    const auto wa = idx < a.size() ? a[idx] : 0;
    const auto wb = idx < b.size() ? b[idx] : 0;
    if(wa != wb) { 
      return wa > wb ? 1 : -1; 
    }
  }
  return 0;
}

bool is_zero(std::vector<uint32_t>& value) {
  for(auto val : value) { 
    if(val) {
      return false;
    }
  }
  return true;
}

// Remove leading zero words
void clamp(std::vector<uint32_t>& bn) {
  const auto size = bn.size();
  if(!size || bn[size-1]) {
    return;
  }
  for(auto i = size-2; i+1; i--) {
    if(bn[i]) {
      bn.resize(i + 1);
      return;
    }
  }
  bn.clear();
}

// Subtract b from a inplace
// a >= b must be guaranteed by caller
void subfrom(std::vector<uint32_t>& a, std::vector<uint32_t>& b) {
  uint32_t borrow = 0;
  for(std::size_t i = 0; i < b.size(); i++) {
    if(b[i] || borrow) {
        const auto w = a[i] - b[i] - borrow;
        // this relies on the automatic w = w (mod base),
        // assuming unsigned max is base-1
        // if this is not the case, w must be set to w % base here
        borrow = w >= a[i];
        a[i] = w;
    }
  }
  for(auto i = b.size(); borrow; i++) {
    borrow = !a[i];
    --a[i];
    // a[i] must be set modulo base here too
    // (this is automatic when base is unsigned max + 1)
  }
}

// Divide bn by 2, truncating any fraction
void shift_right_one(std::vector<uint32_t>& bn) {
  uint32_t carry = 0;
  for(auto i = bn.size(); i > 0; i--) {
    const auto next_carry = (bn[i-1] & 1) ? HI_BIT_SET : 0;
    bn[i-1] >>= 1;
    bn[i-1] |= carry;
    carry = next_carry;
  }
  clamp(bn);
}

// Multiply bn by 2
void shift_left_one(std::vector<uint32_t>& bn) {
  uint32_t carry = 0;
  for(std::size_t i = 0; i < bn.size(); i++) {
      const uint32_t next_carry = !!(bn[i] & HI_BIT_SET);
      bn[i] <<= 1;
      bn[i] |= carry;
      carry = next_carry;
  }
  if(carry) {
    bn.push_back(1);
  }
}

// Set an indexed bit in bn, growing the vector when required
void set_bit_at(std::vector<uint32_t>& bn, std::size_t index, bool set) {
  std::size_t widx = index / (sizeof(uint32_t) * 8);
  std::size_t bidx = index % (sizeof(uint32_t) * 8);
  if(bn.size() < widx + 1) {
    bn.resize(widx + 1);
  }
  if(set) {
    bn[widx] |= uint32_t(1) << bidx;
  } else {
    bn[widx] &= ~(uint32_t(1) << bidx);
  }
}

// Divide n by d, returning the result and leaving the remainder in n
std::vector<uint32_t> divide(std::vector<uint32_t>& n, std::vector<uint32_t> d) {
  if(is_zero(d)) {
    throw(std::runtime_error("Divide by 0."));
  }
  std::size_t shift = 0;
  while(compare(n, d) == 1) {
    shift_left_one(d);
    shift++;
  }
  std::vector<uint32_t> result;
  do {
    if(compare(n, d) >= 0) {
      set_bit_at(result, shift);
      subfrom(n, d);
    }
    shift_right_one(d);
  } while(shift--);
  clamp(result);
  clamp(n);
  return result;
}

std::string to_string(const BigNumber& bn) {
  IppsBigNumSGN bnSgn;
  ippsRef_BN(&bnSgn, NULL, NULL, bn);
  std::string result;
  result.append(1, (bnSgn == ippBigNumNEG) ? '-' : ' ');
  std::vector<uint32_t> vec;
  bn.num2vec(vec);
  do {
      const auto next_bn = divide(vec, {10});
      const char digit_value = static_cast<char>(vec.size()? vec[0] : 0);
      result.push_back('0' + digit_value);
      vec = next_bn;
  } while(!is_zero(vec));

  std::reverse(result.begin()+1, result.end());
  return result;
}

// TODO: combine with the below as a template function?
ipcl::CipherText to_ipcl_ciphertext(const PublicKey& pk, ConstSpan<Ciphertext> ct) {
  std::vector<BigNumber> bn_vec;
  size_t ct_size = ct.size();
  for (size_t i = 0; i < ct_size; i++) {
    bn_vec.push_back(ct[i]->bn_);
  }
  ipcl::CipherText ipcl_ct(pk.ipcl_pubkey_, bn_vec);
  return ipcl_ct;
}

ipcl::PlainText to_ipcl_plaintext(ConstSpan<Plaintext> pt) {
  std::vector<BigNumber> bn_vec;
  size_t pt_size = pt.size();
  for (size_t i = 0; i < pt_size; i++) {
    bn_vec.push_back(pt[i]->bn_);
  }
  ipcl::PlainText ipcl_pt(bn_vec);
  return ipcl_pt;
}
}
