// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ipcl/bignum.h"
#include "ipcl/ciphertext.hpp"
#include "ipcl/plaintext.hpp"

#include "heu/library/algorithms/paillier_ipcl/ciphertext.h"
#include "heu/library/algorithms/paillier_ipcl/public_key.h"

namespace heu::lib::algorithms::paillier_ipcl {

// HI_BIT_SET is base/2
// Assumes CHAR_BIT == 8
const auto HI_BIT_SET = uint32_t(1) << (sizeof(uint32_t) * 8 - 1);
const int BN_DIGITS = 32;
const uint32_t UINT32_MASK = 0xFFFFFFFF;

int Compare(const std::vector<uint32_t>& a, const std::vector<uint32_t>& b);
bool IsZero(std::vector<uint32_t>& value);
void Clamp(std::vector<uint32_t>& bn);
void SubFrom(std::vector<uint32_t>& a, const std::vector<uint32_t>& b);
void ShiftRightOne(std::vector<uint32_t>& bn);
void ShiftLeftOne(std::vector<uint32_t>& bn);
void ShiftRightN(std::vector<uint32_t>& bn, int n);
void ShiftLeftN(std::vector<uint32_t>& bn, int n);
void SetBitAt(std::vector<uint32_t>& bn, std::size_t index, bool set = true);
std::vector<uint32_t> Divide(std::vector<uint32_t>& n, std::vector<uint32_t> d);
std::string ToString(const BigNumber& bn);
ipcl::CipherText ToIpclCiphertext(const PublicKey& pk,
                                  ConstSpan<Ciphertext> ct);
ipcl::PlainText ToIpclPlaintext(ConstSpan<Plaintext> pt);

template <typename T1, typename T2>
std::vector<T1> IpclToHeu(const T2& value) {
  if constexpr ((std::is_same<T1, Plaintext>::value &&
                 std::is_same<T2, ipcl::PlainText>::value) ||
                (std::is_same<T1, Ciphertext>::value &&
                 std::is_same<T2, ipcl::CipherText>::value)) {
    std::vector<BigNumber> bn_data = value.getTexts();
    size_t bn_size = value.getSize();
    std::vector<T1> result;
    result.reserve(bn_size);
    for (size_t i = 0; i < bn_size; i++) {
      result.push_back(T1(bn_data[i]));
    }
    return result;
  } else {
    YACL_THROW("ipcl_to_heu: data type mismatch.");
  }
}

template <typename T>
void ValueVecToPtsVec(std::vector<T>& value_vec, std::vector<T*>& pts_vec) {
  int size = value_vec.size();
  for (int i = 0; i < size; i++) {
    pts_vec.push_back(&value_vec[i]);
  }
}

}  // namespace heu::lib::algorithms::paillier_ipcl
