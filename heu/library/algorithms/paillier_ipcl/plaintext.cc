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

#include <algorithm>
#include "yacl/base/int128.h"
#include "ipcl/utils/common.hpp"
#include "heu/library/algorithms/paillier_ipcl/plaintext.h"
#include "heu/library/algorithms/paillier_ipcl/utils.h"
#include "cereal/archives/portable_binary.hpp"

namespace heu::lib::algorithms::paillier_ipcl {

template <>
void Plaintext::Set(BigNumber value) {
  bn_ = value;
}

template <>
void Plaintext::Set(Plaintext value) {
  bn_ = value.bn_;
}

template <>
void Plaintext::Set(uint8_t value) {
  bn_ = BigNumber((uint32_t)value);
}

template <>
void Plaintext::Set(uint16_t value) {
  bn_ = BigNumber((uint32_t)value);
}

template <>
void Plaintext::Set(uint32_t value) {
  bn_ = BigNumber(value);
}

template <>
void Plaintext::Set(uint64_t value) {
  uint32_t val[2];
  val[0] = value & 0xFFFFFFFF;
  val[1] = (value >> 32) & 0xFFFFFFFF;
  bn_ = BigNumber(val, 2);
}

template <>
void Plaintext::Set(uint128_t value) {
  uint32_t val[4];
  val[0] = value & 0xFFFFFFFF;
  val[1] = (value >> 32) & 0xFFFFFFFF;
  val[2] = (value >> 64) & 0xFFFFFFFF;
  val[3] = (value >> 96) & 0xFFFFFFFF;
  bn_ = BigNumber(val, 4);
}

template <>
void Plaintext::Set(int8_t value) {
  bn_ = BigNumber((int32_t)value);
}

template <>
void Plaintext::Set(int16_t value) {
  bn_ = BigNumber((int32_t)value);
}

template <>
void Plaintext::Set(int32_t value) {
  bn_ = BigNumber(value);
}

template <>
void Plaintext::Set(int64_t value) {
  uint64_t avalue = value > 0 ? value : -value;
  auto sign = value > 0 ? IppsBigNumPOS : IppsBigNumNEG;
  uint32_t val[2];
  val[0] = avalue & 0xFFFFFFFF;
  val[1] = (avalue >> 32) & 0xFFFFFFFF;
  bn_ = BigNumber(val, 2, sign);
}

template <>
void Plaintext::Set(int128_t value) {
  uint128_t avalue = value > 0 ? value : -value;
  auto sign = value > 0 ? IppsBigNumPOS : IppsBigNumNEG;
  uint32_t val[4];
  val[0] = avalue & 0xFFFFFFFF;
  val[1] = (avalue >> 32) & 0xFFFFFFFF;
  val[2] = (avalue >> 64) & 0xFFFFFFFF;
  val[3] = (avalue >> 96) & 0xFFFFFFFF;
  bn_ = BigNumber(val, 4, sign);
}

void Plaintext::Set(const std::string &num, int radix) {
  bn_ = BigNumber(num.c_str());
}

template <>
uint8_t Plaintext::Get() const {
    std::vector<uint32_t> vec;
    bn_.num2vec(vec);
    uint8_t value = vec[0] & 0xFF;
    return value;
}

template <>
uint16_t Plaintext::Get() const {
    std::vector<uint32_t> vec;
    bn_.num2vec(vec);
    uint16_t value = vec[0] & 0xFFFF;
    return value;
}

template <>
uint32_t Plaintext::Get() const {
    std::vector<uint32_t> vec;
    bn_.num2vec(vec);
    return vec[0];
}

template <>
uint64_t Plaintext::Get() const {
    std::vector<uint32_t> vec;
    bn_.num2vec(vec);
    auto size = std::min((int)vec.size(), 2);
    uint64_t value = 0;
    for (auto i = 0; i < size; i++) {
      value += (uint64_t)vec[i] << i * 32;
    }
    return value;
}

template <>
uint128_t Plaintext::Get() const {
  std::vector<uint32_t> vec;
  bn_.num2vec(vec);
  auto size = std::min((int)vec.size(), 4);
  uint128_t value = 0;
  for (auto i = 0; i < size; i++) {
    value += (uint128_t)vec[i] << i * 32;
  }
  return value;
}

template <>
int8_t Plaintext::Get() const {
  IppsBigNumSGN sign;
  uint32_t* data;
  ippsRef_BN(&sign, nullptr, &data, bn_);
  uint8_t avalue = data[0] & 0xFF;
  int8_t value = sign == IppsBigNumPOS? avalue : -avalue;
  return value;
}

template <>
int16_t Plaintext::Get() const {
  IppsBigNumSGN sign;
  uint32_t* data;
  ippsRef_BN(&sign, nullptr, &data, bn_);
  uint16_t avalue = data[0] & 0xFFFF;
  int16_t value = sign == IppsBigNumPOS? avalue : -avalue;
  return value;
}

template <>
int32_t Plaintext::Get() const {
  IppsBigNumSGN sign;
  uint32_t* data;
  ippsRef_BN(&sign, nullptr, &data, bn_);
  int32_t value = sign == IppsBigNumPOS? data[0] : -data[0];
  return value;
}

template <>
int64_t Plaintext::Get() const {
  IppsBigNumSGN sign;
  uint32_t* data;
  int bit_size;
  ippsRef_BN(&sign, &bit_size, &data, bn_);
  auto size = std::min((bit_size + 31) >> 5, 2);
  uint64_t avalue = 0;
  for (auto i = 0; i < size; i++) {
    avalue += (uint64_t)data[i] << i * 32;
  }
  int64_t value = sign == IppsBigNumPOS? avalue : -avalue;
  return value;
}

template <>
int128_t Plaintext::Get() const {
  IppsBigNumSGN sign;
  uint32_t* data;
  int bit_size;
  ippsRef_BN(&sign, &bit_size, &data, bn_);
  auto size = std::min((bit_size + 31) >> 5, 4);
  uint128_t avalue = 0;
  for (auto i = 0; i < size; i++) {
    avalue += (uint128_t)data[i] << i * 32;
  }
  int128_t value = sign == IppsBigNumPOS? avalue : -avalue;
  return value;
}

yacl::Buffer Plaintext::Serialize() const {
  std::ostringstream os;
  {
    cereal::PortableBinaryOutputArchive archive(os);
    archive(bn_);
  }
  yacl::Buffer buf(os.str().data(), os.str().size());
  return buf;
}

void Plaintext::Deserialize(yacl::ByteContainerView buffer) {
  std::istringstream is((std::string)buffer);
  {
    cereal::PortableBinaryInputArchive archive(is);
    archive(bn_);
  }
}

std::string Plaintext::ToString() const {
  return to_string(bn_);
}

std::ostream &operator<<(std::ostream &os, const Plaintext &pt) {
  os << pt.ToString();
  return os;
}

std::string Plaintext::ToHexString() const {
  std::string s;
  bn_.num2hex(s);
  return s;
}

// yacl::Buffer Plaintext::ToBytes(size_t byte_len, Endian endian = Endian::native) const {
//   throw std::runtime_error("Not implemented.");
// }

// void Plaintext::ToBytes(unsigned char *buf, size_t buf_len,
//               Endian endian = Endian::native) const {
//   throw std::runtime_error("Not implemented.");
// }

Plaintext Plaintext::operator-() const {
  Plaintext result;
  IppsBigNumSGN sign;
  int bit_len;
  Ipp32u* data;
  ippsRef_BN(&sign, &bit_len, &data, bn_);
  auto rev_sign = (sign == IppsBigNumPOS)? IppsBigNumNEG : IppsBigNumPOS;
  result.bn_ = BigNumber(data, bit_len, rev_sign);
  return result;
}

void Plaintext::NegInplace() {
  *this = -(*this);
}

size_t Plaintext::BitCount() const {
  return bn_.BitSize();
}

Plaintext Plaintext::operator+(const Plaintext &op2) const {
  Plaintext result;
  result.bn_ = bn_ + op2.bn_;
  return result;
}

Plaintext Plaintext::operator-(const Plaintext &op2) const {
  Plaintext result;
  result.bn_ = bn_ - op2.bn_;
  return result;
}

Plaintext Plaintext::operator*(const Plaintext &op2) const {
  Plaintext result;
  result.bn_ = bn_ * op2.bn_;
  return result;
}

Plaintext Plaintext::operator/(const Plaintext &op2) const {
  Plaintext result;
  result.bn_ = bn_ / op2.bn_;
  return result;
}

Plaintext Plaintext::operator%(const Plaintext &op2) const {
  Plaintext result;
  result.bn_ = bn_ % op2.bn_;
  return result;  
}

Plaintext Plaintext::operator|(const Plaintext &op2) const {
  throw std::runtime_error("Not implemented.");
}

Plaintext Plaintext::operator^(const Plaintext &op2) const {
  throw std::runtime_error("Not implemented.");
}

Plaintext Plaintext::operator<<(size_t op2) const {
  throw std::runtime_error("Not implemented.");
}

Plaintext Plaintext::operator>>(size_t op2) const {
  throw std::runtime_error("Not implemented.");
}

Plaintext Plaintext::operator+=(const Plaintext &op2) {
  bn_ += op2.bn_;
  return *this;
}

Plaintext Plaintext::operator-=(const Plaintext &op2) {
  bn_ -= op2.bn_;
  return *this;
}

Plaintext Plaintext::operator*=(const Plaintext &op2) {
  bn_ *= op2.bn_;
  return *this;
}

Plaintext Plaintext::operator/=(const Plaintext &op2) {
  bn_ /= op2.bn_;
  return *this;
}

Plaintext Plaintext::operator%=(const Plaintext &op2) {
  bn_ %= op2.bn_;
  return *this;
}

Plaintext Plaintext::operator&=(const Plaintext &op2) {
  throw std::runtime_error("Not implemented.");
}
Plaintext Plaintext::operator|=(const Plaintext &op2) {
  throw std::runtime_error("Not implemented.");
}
Plaintext Plaintext::operator^=(const Plaintext &op2) {
  throw std::runtime_error("Not implemented.");
}
Plaintext Plaintext::operator<<=(size_t op2) {
  throw std::runtime_error("Not implemented.");
}
Plaintext Plaintext::operator>>=(size_t op2) {
  throw std::runtime_error("Not implemented.");
}

bool Plaintext::operator>(const Plaintext &other) const {
  return bn_ > other.bn_;
}

bool Plaintext::operator<(const Plaintext &other) const {
  return bn_ < other.bn_;
}

bool Plaintext::operator>=(const Plaintext &other) const {
  return bn_ >= other.bn_;
}

bool Plaintext::operator<=(const Plaintext &other) const {
  return bn_ <= other.bn_;
}

bool Plaintext::operator==(const Plaintext &other) const {
  return bn_ == other.bn_;
}

bool Plaintext::operator!=(const Plaintext &other) const {
  return bn_ != other.bn_;
}

void Plaintext::RandomExactBits(size_t bit_size, Plaintext *r) {
  r->bn_ = ipcl::getRandomBN(bit_size);
}

void Plaintext::RandomLtN(const Plaintext &n, Plaintext *r) {
  do {
    Plaintext::RandomExactBits(n.BitCount(), r);
  } while (r->IsNegative() || (*r >= n));
}
}