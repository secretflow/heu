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

#include "heu/library/phe/base/serializable_types.h"
#include "heu/library/phe/base/variant_helper.h"

namespace heu::lib::phe {

class Plaintext : public SerializableVariant<HE_PLAINTEXT_TYPES> {
 public:
  using SerializableVariant<HE_PLAINTEXT_TYPES>::SerializableVariant;
  using SerializableVariant<HE_PLAINTEXT_TYPES>::operator=;
  template <typename T, std::enable_if_t<std::is_fundamental_v<T>, int> = 0>
  Plaintext(SchemaType schema, T init_value) : Plaintext(schema) {
    SetValue(init_value);
  }

  template <typename T, std::enable_if_t<std::is_fundamental_v<T>, int> = 0>
  [[nodiscard]] T GetValue() const {
    return Visit([](const auto &pt) -> T {
      FOR_EACH_TYPE(pt) return pt.template Get<T>();
    });
  }

  template <typename T, std::enable_if_t<std::is_fundamental_v<T>, int> = 0>
  void SetValue(T value) {
    Visit([&value](auto &pt) { FOR_EACH_TYPE(pt) pt.template Set<T>(value); });
  }

  void SetValue(const std::string &num, int radix);

  size_t BitCount() const;
  yacl::Buffer ToBytes(size_t byte_len, algorithms::Endian endian =
                                            algorithms::Endian::native) const;
  void ToBytes(unsigned char *buf, size_t buf_len,
               algorithms::Endian endian = algorithms::Endian::native) const;

  [[nodiscard]] std::string ToHexString() const;

  Plaintext operator-() const;
  void NegateInplace();

  bool IsZero() const;
  bool IsPositive() const;
  bool IsNegative() const;

  Plaintext operator+(const Plaintext &operand2) const;
  Plaintext operator-(const Plaintext &operand2) const;
  Plaintext operator*(const Plaintext &operand2) const;
  Plaintext operator/(const Plaintext &operand2) const;
  Plaintext operator%(const Plaintext &operand2) const;

  Plaintext operator&(const Plaintext &operand2) const;
  Plaintext operator|(const Plaintext &operand2) const;
  Plaintext operator^(const Plaintext &operand2) const;
  Plaintext operator<<(size_t operand2) const;
  Plaintext operator>>(size_t operand2) const;

  Plaintext operator+=(const Plaintext &operand2);
  Plaintext operator-=(const Plaintext &operand2);
  Plaintext operator*=(const Plaintext &operand2);
  Plaintext operator/=(const Plaintext &operand2);
  Plaintext operator%=(const Plaintext &operand2);

  Plaintext operator&=(const Plaintext &operand2);
  Plaintext operator|=(const Plaintext &operand2);
  Plaintext operator^=(const Plaintext &operand2);
  Plaintext operator<<=(size_t operand2);
  Plaintext operator>>=(size_t operand2);

  bool operator>(const Plaintext &other) const;
  bool operator<(const Plaintext &other) const;
  bool operator>=(const Plaintext &other) const;
  bool operator<=(const Plaintext &other) const;
  bool operator==(const Plaintext &other) const;
  bool operator!=(const Plaintext &other) const;

  // static helper functions
  static void RandomExactBits(SchemaType ir, size_t bit_size, Plaintext *r);
  static void RandomLtN(const Plaintext &ir, Plaintext *r);
};

}  // namespace heu::lib::phe
