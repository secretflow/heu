// Copyright 2023 Clustar Technology Co., Ltd.
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

#include "msgpack.hpp"
#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

class Plaintext {
public:
    Plaintext() = default;

    template <typename T>
    explicit Plaintext(T& value) {
      Set(value);
    }

    Plaintext(const Plaintext& other);
    Plaintext(Plaintext&& other);

    ~Plaintext() = default;

    Plaintext& operator=(const Plaintext& other);
    Plaintext& operator=(Plaintext&& other);

    // Plaintext -> primitive type
    // T could be (u)int8/16/32/64/128
    // Notice:
    // Get(float/doube value) is OK, BUT, only integer part is read
    template <typename T>
    T Get() const;

    // Set primitive value
    // T could be (u)int8/16/32/64/128
    // Notice:
    // Set(float/double value) is OK, BUT, only integer part is stored
    template <typename T>
    void Set(T value);

    // Set big number by string
    // Notice: 
    // 1) Do Not add prefix in num;
    // Set(0x123, 16) -> Set(123, 16)
    // 2) Do Not support float/double
    // Set(1.23, 10) is WRONG
    void Set(const std::string &num, int radix);

    yacl::Buffer Serialize() const;
    void Deserialize(yacl::ByteContainerView buffer);   

    std::string ToString() const;
    friend std::ostream &operator<<(std::ostream &os, const Plaintext &pt);
    // Notince: capital letter
    std::string ToHexString() const;

    yacl::Buffer ToBytes(size_t byte_len, Endian endian = Endian::native) const;
    void ToBytes(unsigned char *buf, size_t buf_len,
                Endian endian = Endian::native) const;

    // Exact bit counts
    size_t BitCount() const;

    Plaintext operator-() const;
    void NegateInplace();

    bool IsNegative() const;

    bool IsZero() const;

    bool IsPositive() const;

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

    int CompareAbs(const Plaintext &other) const;

private:
  void Negate(Plaintext *z) const;

private:
    MPInt mp_int_;
};

} // heu::lib::algorithms::paillier_clustar_fpga

namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
  namespace adaptor {

  template <>
  struct pack<heu::lib::algorithms::paillier_clustar_fpga::Plaintext> {
    template <typename Stream>
    msgpack::packer<Stream> &operator()(
        msgpack::packer<Stream> &object,
        const heu::lib::algorithms::paillier_clustar_fpga::Plaintext &mp) const {
      object.pack(std::string_view(mp.Serialize()));
      return object;
    }
  };

  template <>
  struct convert<heu::lib::algorithms::paillier_clustar_fpga::Plaintext> {
    const msgpack::object &operator()(const msgpack::object &object,
                                      heu::lib::algorithms::paillier_clustar_fpga::Plaintext &mp) const {
      mp.Deserialize(object.as<std::string_view>());
      return object;
    }
  };

  }  // namespace adaptor
}  // MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
}  // namespace msgpack
