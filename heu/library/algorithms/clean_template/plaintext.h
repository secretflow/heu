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

#include "yasl/base/byte_container_view.h"

#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::your_algo {

class Plaintext {
 public:
  explicit Plaintext() = default;

  // Plaintext -> primitive type
  // T could be (u)int8/16/32/64/128
  template <typename T>
  T Get() const;

  // Set primitive value
  // T could be (u)int8/16/32/64/128
  template <typename T>
  void Set(T value);
  // Set big number by string
  void Set(const std::string &num, int radix);

  yasl::Buffer Serialize() const;
  void Deserialize(yasl::ByteContainerView buffer);

  std::string ToString() const;
  friend std::ostream &operator<<(std::ostream &os, const Plaintext &pt);
  std::string ToHexString() const;

  yasl::Buffer ToBytes(size_t byte_len, Endian endian = Endian::native) const;
  void ToBytes(unsigned char *buf, size_t buf_len,
               Endian endian = Endian::native) const;

  size_t BitCount() const;

  Plaintext operator-() const;
  void NegInplace();

  bool IsZero() const;      // [SPI: Critical]
  bool IsPositive() const;  // [SPI: Important]
  bool IsNegative() const;  // [SPI: Important]

  Plaintext operator+(const Plaintext &op2) const;
  Plaintext operator-(const Plaintext &op2) const;
  Plaintext operator*(const Plaintext &op2) const;
  Plaintext operator/(const Plaintext &op2) const;
  Plaintext operator%(const Plaintext &op2) const;
  Plaintext operator&(const Plaintext &op2) const;
  Plaintext operator|(const Plaintext &op2) const;
  Plaintext operator^(const Plaintext &op2) const;
  Plaintext operator<<(size_t op2) const;
  Plaintext operator>>(size_t op2) const;

  Plaintext operator+=(const Plaintext &op2);
  Plaintext operator-=(const Plaintext &op2);
  Plaintext operator*=(const Plaintext &op2);
  Plaintext operator/=(const Plaintext &op2);
  Plaintext operator%=(const Plaintext &op2);
  Plaintext operator&=(const Plaintext &op2);
  Plaintext operator|=(const Plaintext &op2);
  Plaintext operator^=(const Plaintext &op2);
  Plaintext operator<<=(size_t op2);
  Plaintext operator>>=(size_t op2);

  bool operator>(const Plaintext &other) const;
  bool operator<(const Plaintext &other) const;
  bool operator>=(const Plaintext &other) const;
  bool operator<=(const Plaintext &other) const;
  bool operator==(const Plaintext &other) const;
  bool operator!=(const Plaintext &other) const;

  // static helper functions //
  // Generates a uniformly distributed random number of "bit_size" size
  static void RandomExactBits(size_t bit_size, Plaintext *r);
  // Generates a uniformly distributed random number in [0, N)
  static void RandomLtN(const Plaintext &n, Plaintext *r);
};

}  // namespace heu::lib::algorithms::your_algo
