// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ipcl/bignum.h"
#include "yacl/base/byte_container_view.h"

#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_ipcl {

class Plaintext {
 public:
  explicit Plaintext() = default;

  template <typename T>
  explicit Plaintext(T &value) {
    Set(value);
  }

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

  yacl::Buffer Serialize() const;
  void Deserialize(yacl::ByteContainerView buffer);

  std::string ToString() const;
  friend std::ostream &operator<<(std::ostream &os, const Plaintext &pt);
  std::string ToHexString() const;

  yacl::Buffer ToBytes(size_t byte_len, Endian endian = Endian::native) const;
  void ToBytes(unsigned char *buf, size_t buf_len,
               Endian endian = Endian::native) const;

  size_t BitCount() const;

  Plaintext operator-() const;
  void NegateInplace();

  inline bool IsNegative() const { return bn_ < BigNumber::Zero(); };

  inline bool IsZero() const { return bn_ == BigNumber::Zero(); }

  inline bool IsPositive() const { return bn_ > BigNumber::Zero(); }

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

  // static helper functions
  static void RandomExactBits(size_t bit_size, Plaintext *r);
  static void RandomLtN(const Plaintext &n, Plaintext *r);

  static Plaintext Absolute(const Plaintext &pt);

  operator BigNumber() { return bn_; }

  BigNumber bn_;
};

}  // namespace heu::lib::algorithms::paillier_ipcl
