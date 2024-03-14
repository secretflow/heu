// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "utils.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

namespace heu::lib::algorithms::paillier_ipcl {

// Compile a with b, returning 1:a>b, 0:a==b, -1:a<b
int Compare(const std::vector<uint32_t> &a, const std::vector<uint32_t> &b) {
  const auto max_size = std::max(a.size(), b.size());
  for (auto i = max_size; i > 0; i--) {
    auto idx = i - 1;
    const auto wa = idx < a.size() ? a[idx] : 0;
    const auto wb = idx < b.size() ? b[idx] : 0;
    if (wa != wb) {
      return wa > wb ? 1 : -1;
    }
  }
  return 0;
}

bool IsZero(std::vector<uint32_t> &value) {
  for (auto val : value) {
    if (val) {
      return false;
    }
  }
  return true;
}

// Remove leading zero words
void Clamp(std::vector<uint32_t> &bn) {
  const auto size = bn.size();
  if (!size || bn[size - 1]) {
    return;
  }
  for (auto i = size - 2; i + 1; i--) {
    if (bn[i]) {
      bn.resize(i + 1);
      return;
    }
  }
  bn.clear();
}

// Subtract b from a inplace
// a >= b must be guaranteed by caller
void SubFrom(std::vector<uint32_t> &a, std::vector<uint32_t> &b) {
  uint32_t borrow = 0;
  for (std::size_t i = 0; i < b.size(); i++) {
    if (b[i] || borrow) {
      const auto w = a[i] - b[i] - borrow;
      // this relies on the automatic w = w (mod base),
      // assuming unsigned max is base-1
      // if this is not the case, w must be set to w % base here
      borrow = w >= a[i];
      a[i] = w;
    }
  }
  for (auto i = b.size(); borrow; i++) {
    borrow = !a[i];
    --a[i];
    // a[i] must be set modulo base here too
    // (this is automatic when base is unsigned max + 1)
  }
}

// Divide bn by 2, truncating any fraction
void ShiftRightOne(std::vector<uint32_t> &bn) {
  uint32_t carry = 0;
  for (auto i = bn.size(); i > 0; i--) {
    const auto next_carry = (bn[i - 1] & 1) ? HI_BIT_SET : 0;
    bn[i - 1] >>= 1;
    bn[i - 1] |= carry;
    carry = next_carry;
  }
  Clamp(bn);
}

// Multiply bn by 2
void ShiftLeftOne(std::vector<uint32_t> &bn) {
  uint32_t carry = 0;
  for (std::size_t i = 0; i < bn.size(); i++) {
    const uint32_t next_carry = !!(bn[i] & HI_BIT_SET);
    bn[i] <<= 1;
    bn[i] |= carry;
    carry = next_carry;
  }
  if (carry) {
    bn.push_back(1);
  }
}

void ShiftRightN(std::vector<uint32_t> &bn, int n) {
  int num_digits = 0;
  int remainder = 0;
  uint32_t mask;
  uint32_t shift;
  uint32_t carry = 0;
  uint32_t next_carry;
  if (n > BN_DIGITS) {
    num_digits = n / BN_DIGITS;
    remainder = n % BN_DIGITS;
  } else {
    remainder = n;
  }
  if (remainder > 0) {
    int size = bn.size();
    mask = ((uint32_t)1 << remainder) - (uint32_t)1;
    shift = BN_DIGITS - remainder;
    for (int i = size - 1; i >= 0; i--) {
      next_carry = bn[i] & mask;
      bn[i] = (bn[i] >> remainder) | (carry << shift);
      carry = next_carry;
    }
  }
  if (num_digits > 0) {
    bn.erase(bn.begin(), bn.begin() + num_digits);
  }
  // Clamp(bn);
}

void ShiftLeftN(std::vector<uint32_t> &bn, int n) {
  int num_digits = 0;
  int remainder = 0;
  uint32_t mask;
  uint32_t shift;
  uint32_t carry = 0;
  uint32_t next_carry;
  if (n > BN_DIGITS) {
    num_digits = n / BN_DIGITS;
    remainder = n % BN_DIGITS;
  } else {
    remainder = n;
  }
  if (remainder > 0) {
    size_t size = bn.size();
    mask = ((uint32_t)1 << remainder) - (uint32_t)1;
    shift = BN_DIGITS - remainder;
    for (size_t i = 0; i < size; i++) {
      next_carry = (bn[i] >> shift) & mask;
      bn[i] = (bn[i] << remainder) | carry;
      carry = next_carry;
    }
    if (carry != 0) {
      bn.push_back(carry);
    }
  }
  if (num_digits > 0) {
    bn.insert(bn.begin(), num_digits, 0);
  }
  // Clamp(bn);
}

// Set an indexed bit in bn, growing the vector when required
void SetBitAt(std::vector<uint32_t> &bn, std::size_t index, bool set) {
  std::size_t widx = index / (sizeof(uint32_t) * 8);
  std::size_t bidx = index % (sizeof(uint32_t) * 8);
  if (bn.size() < widx + 1) {
    bn.resize(widx + 1);
  }
  if (set) {
    bn[widx] |= uint32_t(1) << bidx;
  } else {
    bn[widx] &= ~(uint32_t(1) << bidx);
  }
}

// Divide n by d, returning the result and leaving the remainder in n
std::vector<uint32_t> Divide(std::vector<uint32_t> &n,
                             std::vector<uint32_t> d) {
  if (IsZero(d)) {
    YACL_THROW("Divide by 0.");
  }
  std::size_t shift = 0;
  while (Compare(n, d) == 1) {
    ShiftLeftOne(d);
    shift++;
  }
  std::vector<uint32_t> result;
  do {
    if (Compare(n, d) >= 0) {
      SetBitAt(result, shift);
      SubFrom(n, d);
    }
    ShiftRightOne(d);
  } while (shift--);
  Clamp(result);
  Clamp(n);
  return result;
}

std::string ToString(const BigNumber &bn) {
  IppsBigNumSGN bnSgn;
  ippsRef_BN(&bnSgn, NULL, NULL, bn);
  std::string result;
  result.append(1, (bnSgn == ippBigNumNEG) ? '-' : ' ');
  std::vector<uint32_t> vec;
  bn.num2vec(vec);
  do {
    const auto next_bn = Divide(vec, {10});
    const char digit_value = static_cast<char>(vec.size() ? vec[0] : 0);
    result.push_back('0' + digit_value);
    vec = next_bn;
  } while (!IsZero(vec));

  std::reverse(result.begin() + 1, result.end());
  return result;
}

// TODO: combine with the below as a template function?
ipcl::CipherText ToIpclCiphertext(const PublicKey &pk,
                                  ConstSpan<Ciphertext> ct) {
  std::vector<BigNumber> bn_vec;
  size_t ct_size = ct.size();
  for (size_t i = 0; i < ct_size; i++) {
    bn_vec.push_back(ct[i]->bn_);
  }
  ipcl::CipherText ipcl_ct(pk.ipcl_pubkey_, bn_vec);
  return ipcl_ct;
}

ipcl::PlainText ToIpclPlaintext(ConstSpan<Plaintext> pt) {
  std::vector<BigNumber> bn_vec;
  size_t pt_size = pt.size();
  for (size_t i = 0; i < pt_size; i++) {
    bn_vec.push_back(pt[i]->bn_);
  }
  ipcl::PlainText ipcl_pt(bn_vec);
  return ipcl_pt;
}
}  // namespace heu::lib::algorithms::paillier_ipcl
