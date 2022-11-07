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

#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::algorithms::mock {

class Plaintext {
 public:
  // [SPI: Critical]
  explicit Plaintext() = default;

  // init with primitive value
  // T could be (u)int8/16/32/64/128
  template <typename T>
  explicit Plaintext(T value) {
    Set(value);
  }

  // Plaintext -> primitive type
  // T could be (u)int8/16/32/64/128
  // [SPI: Critical]
  template <typename T>
  [[nodiscard]] T Get() const {
    if constexpr (std::is_same_v<T, MPInt>) {
      return bn_;  // do convert to MPInt
    }

    return bn_.template Get<T>();
  }

  // Set primitive value
  // T could be (u)int8/16/32/64/128
  // [SPI: Critical]
  template <typename T>
  void Set(T value) {
    bn_.template Set(value);
  }

  // [SPI: Critical]
  void Set(const std::string &num, int radix) { bn_.Set(num, radix); }

  // [SPI: Critical]
  [[nodiscard]] yasl::Buffer Serialize() const { return bn_.Serialize(); }

  // [SPI: Critical]
  void Deserialize(yasl::ByteContainerView buffer) { bn_.Deserialize(buffer); }

  // [SPI: Critical]
  [[nodiscard]] std::string ToString() const { return bn_.ToString(); }
  // [SPI: Important]
  friend std::ostream &operator<<(std::ostream &os, const Plaintext &pt) {
    return os << pt.ToString();
  }

  // [SPI: Critical]
  [[nodiscard]] std::string ToHexString() const { return bn_.ToHexString(); }

  // [SPI: Critical]
  yasl::Buffer ToBytes(size_t byte_len, Endian endian = Endian::native) const {
    return bn_.ToBytes(byte_len, endian);
  }

  // [SPI: Critical]
  void ToBytes(unsigned char *buf, size_t buf_len,
               Endian endian = Endian::native) const {
    bn_.ToBytes(buf, buf_len, endian);
  }

  size_t BitCount() const { return bn_.BitCount(); }  // [SPI: Critical]

  Plaintext operator-() const { return Wrap(-bn_); }  // [SPI: Critical]
  void NegInplace() { bn_.NegInplace(); }             // [SPI: Critical]

  // [SPI: Critical]
  Plaintext operator+(const Plaintext &op2) const {
    return Wrap(bn_ + op2.bn_);
  }
  // [SPI: Critical]
  Plaintext operator-(const Plaintext &op2) const {
    return Wrap(bn_ - op2.bn_);
  }
  // [SPI: Critical]
  Plaintext operator*(const Plaintext &op2) const {
    return Wrap(bn_ * op2.bn_);
  }
  // [SPI: Important]
  Plaintext operator/(const Plaintext &op2) const {
    return Wrap(bn_ / op2.bn_);
  }
  // [SPI: Important]
  Plaintext operator%(const Plaintext &op2) const {
    return Wrap(bn_ % op2.bn_);
  }
  // [SPI: Important]
  Plaintext operator&(const Plaintext &op2) const {
    return Wrap(bn_ & op2.bn_);
  }
  // [SPI: Important]
  Plaintext operator|(const Plaintext &op2) const {
    return Wrap(bn_ | op2.bn_);
  }
  // [SPI: Important]
  Plaintext operator^(const Plaintext &op2) const {
    return Wrap(bn_ ^ op2.bn_);
  }

  // [SPI: Important]
  Plaintext operator<<(size_t op2) const { return Wrap(bn_ << op2); }
  // [SPI: Important]
  Plaintext operator>>(size_t op2) const { return Wrap(bn_ >> op2); }

  // [SPI: Critical]
  Plaintext operator+=(const Plaintext &op2) {
    bn_ += op2.bn_;
    return *this;
  }

  // [SPI: Critical]
  Plaintext operator-=(const Plaintext &op2) {
    bn_ -= op2.bn_;
    return *this;
  }

  // [SPI: Critical]
  Plaintext operator*=(const Plaintext &op2) {
    bn_ *= op2.bn_;
    return *this;
  }

  // [SPI: Important]
  Plaintext operator/=(const Plaintext &op2) {
    bn_ /= op2.bn_;
    return *this;
  }

  // [SPI: Important]
  Plaintext operator%=(const Plaintext &op2) {
    bn_ %= op2.bn_;
    return *this;
  }

  // [SPI: Important]
  Plaintext operator&=(const Plaintext &op2) {
    bn_ &= op2.bn_;
    return *this;
  }

  // [SPI: Important]
  Plaintext operator|=(const Plaintext &op2) {
    bn_ |= op2.bn_;
    return *this;
  }

  // [SPI: Important]
  Plaintext operator^=(const Plaintext &op2) {
    bn_ ^= op2.bn_;
    return *this;
  }

  // [SPI: Important]
  Plaintext operator<<=(size_t op2) {
    bn_ <<= op2;
    return *this;
  }

  // [SPI: Important]
  Plaintext operator>>=(size_t op2) {
    bn_ >>= op2;
    return *this;
  }

  // [SPI: Important]
  bool operator>(const Plaintext &other) const { return bn_ > other.bn_; }
  // [SPI: Important]
  bool operator<(const Plaintext &other) const { return bn_ < other.bn_; }
  // [SPI: Important]
  bool operator>=(const Plaintext &other) const { return bn_ >= other.bn_; }
  // [SPI: Important]
  bool operator<=(const Plaintext &other) const { return bn_ <= other.bn_; }
  // [SPI: Important]
  bool operator==(const Plaintext &other) const { return bn_ == other.bn_; }
  // [SPI: Important]
  bool operator!=(const Plaintext &other) const { return bn_ != other.bn_; }

  MSGPACK_DEFINE(bn_);
  MPInt bn_;  // It would be better if this field is private.

  // static helper functions
  // [SPI: Critical]
  static void RandomExactBits(size_t bit_size, Plaintext *r) {
    MPInt::RandomExactBits(bit_size, &r->bn_);
  }

  // [SPI: Critical]
  static void RandomLtN(const Plaintext &n, Plaintext *r) {
    MPInt::RandomLtN(n.bn_, &r->bn_);
  }

 private:
  Plaintext Wrap(MPInt value) const {
    Plaintext me;
    me.bn_ = value;
    return me;
  }
};

}  // namespace heu::lib::algorithms::mock
