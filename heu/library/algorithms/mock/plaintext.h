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
  explicit Plaintext() = default;

  template <typename T>
  explicit Plaintext(T value) {
    Set(value);
  }

  // Plaintext -> primitive type
  // T could be (u)int8/16/32/64/128 and MPInt
  template <typename T>
  [[nodiscard]] T Get() const {
    if constexpr (std::is_same_v<T, MPInt>) {
      return real_pt_;  // do convert to MPInt
    }

    return real_pt_.template Get<T>();
  }

  template <typename T>
  void Set(T value) {
    real_pt_.template Set(value);
  }

  void Set(const std::string &num, int radix) { real_pt_.Set(num, radix); }

  [[nodiscard]] yasl::Buffer Serialize() const { return real_pt_.Serialize(); }

  void Deserialize(yasl::ByteContainerView buffer) {
    real_pt_.Deserialize(buffer);
  }

  [[nodiscard]] std::string ToString() const { return real_pt_.ToString(); }
  friend std::ostream &operator<<(std::ostream &os, const Plaintext &pt) {
    return os << pt.ToString();
  }

  [[nodiscard]] std::string ToHexString() const {
    return real_pt_.ToHexString();
  }

  yasl::Buffer ToBytes(size_t byte_len, Endian endian = Endian::native) const {
    return real_pt_.ToBytes(byte_len, endian);
  }

  void ToBytes(unsigned char *buf, size_t buf_len,
               Endian endian = Endian::native) const {
    real_pt_.ToBytes(buf, buf_len, endian);
  }

  size_t BitCount() const { return real_pt_.BitCount(); }

  Plaintext operator-() const { return Wrap(-real_pt_); }
  void NegInplace() { real_pt_.NegInplace(); }

  Plaintext operator+(const Plaintext &op2) const {
    return Wrap(real_pt_ + op2.real_pt_);
  }
  Plaintext operator-(const Plaintext &op2) const {
    return Wrap(real_pt_ - op2.real_pt_);
  }
  Plaintext operator*(const Plaintext &op2) const {
    return Wrap(real_pt_ * op2.real_pt_);
  }
  Plaintext operator/(const Plaintext &op2) const {
    return Wrap(real_pt_ / op2.real_pt_);
  }
  Plaintext operator%(const Plaintext &op2) const {
    return Wrap(real_pt_ % op2.real_pt_);
  }
  Plaintext operator&(const Plaintext &op2) const {
    return Wrap(real_pt_ & op2.real_pt_);
  }
  Plaintext operator|(const Plaintext &op2) const {
    return Wrap(real_pt_ | op2.real_pt_);
  }
  Plaintext operator^(const Plaintext &op2) const {
    return Wrap(real_pt_ ^ op2.real_pt_);
  }

  Plaintext operator<<(size_t op2) const { return Wrap(real_pt_ << op2); }
  Plaintext operator>>(size_t op2) const { return Wrap(real_pt_ >> op2); }

  Plaintext operator+=(const Plaintext &op2) {
    real_pt_ += op2.real_pt_;
    return *this;
  }

  Plaintext operator-=(const Plaintext &op2) {
    real_pt_ -= op2.real_pt_;
    return *this;
  }

  Plaintext operator*=(const Plaintext &op2) {
    real_pt_ *= op2.real_pt_;
    return *this;
  }

  Plaintext operator/=(const Plaintext &op2) {
    real_pt_ /= op2.real_pt_;
    return *this;
  }

  Plaintext operator%=(const Plaintext &op2) {
    real_pt_ %= op2.real_pt_;
    return *this;
  }

  Plaintext operator&=(const Plaintext &op2) {
    real_pt_ &= op2.real_pt_;
    return *this;
  }

  Plaintext operator|=(const Plaintext &op2) {
    real_pt_ |= op2.real_pt_;
    return *this;
  }

  Plaintext operator^=(const Plaintext &op2) {
    real_pt_ ^= op2.real_pt_;
    return *this;
  }

  Plaintext operator<<=(size_t op2) {
    real_pt_ <<= op2;
    return *this;
  }

  Plaintext operator>>=(size_t op2) {
    real_pt_ >>= op2;
    return *this;
  }

  bool operator>(const Plaintext &other) const {
    return real_pt_ > other.real_pt_;
  }

  bool operator<(const Plaintext &other) const {
    return real_pt_ < other.real_pt_;
  }

  bool operator>=(const Plaintext &other) const {
    return real_pt_ >= other.real_pt_;
  }

  bool operator<=(const Plaintext &other) const {
    return real_pt_ <= other.real_pt_;
  }

  bool operator==(const Plaintext &other) const {
    return real_pt_ == other.real_pt_;
  }

  bool operator!=(const Plaintext &other) const {
    return real_pt_ != other.real_pt_;
  }

  MSGPACK_DEFINE(real_pt_);
  MPInt real_pt_;  // you should make this field private

  // static helper functions
  static void RandomExactBits(size_t bit_size, Plaintext *r) {
    MPInt::RandomExactBits(bit_size, &r->real_pt_);
  }

  static void RandomLtN(const Plaintext &n, Plaintext *r) {
    MPInt::RandomLtN(n.real_pt_, &r->real_pt_);
  }

 private:
  Plaintext Wrap(MPInt value) const {
    Plaintext me;
    me.real_pt_ = value;
    return me;
  }
};

}  // namespace heu::lib::algorithms::mock
