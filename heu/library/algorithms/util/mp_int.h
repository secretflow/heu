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

#include <memory>
#include <ostream>
#include <string>

#include "fmt/format.h"
#include "fmt/ostream.h"
#include "msgpack.hpp"
#include "tommath.h"
#include "yasl/base/int128.h"

#include "heu/library/algorithms/util/he_assert.h"

#define MPINT_ENFORCE_OK(MP_ERR, ...) YASL_ENFORCE_EQ((MP_ERR), 0, __VA_ARGS__)

namespace heu::lib::algorithms {

enum class PrimeType : int {
  Normal = 0,
  BBS = 1,  // p = 3 mod 4
  Safe = 2  // (p-1)/2 is prime
};

/**
 * MPInt -- Multiple Precision Integer
 */
class MPInt {
 public:
  // Pre-defined variables ...
  static const MPInt _1_;
  static const MPInt _2_;

  // Constructors and functions ...
  MPInt();
  explicit MPInt(int32_t x);
  explicit MPInt(uint32_t x);
  explicit MPInt(int64_t x);
  explicit MPInt(uint64_t x);
  explicit MPInt(int128_t x);
  explicit MPInt(uint128_t x);
  explicit MPInt(double x);
  MPInt(const std::string &num, int radix);
  MPInt(MPInt &&other) noexcept;
  MPInt(const MPInt &other);

  ~MPInt() { mp_clear(&n_); }

  MPInt &operator=(const MPInt &other);
  MPInt &operator=(MPInt &&other) noexcept;  // not thread safe

  inline bool operator>=(const MPInt &other) const {
    return Compare(other) >= 0;
  }

  inline bool operator<=(const MPInt &other) const {
    return Compare(other) <= 0;
  }

  inline bool operator>(const MPInt &other) const { return Compare(other) > 0; }

  inline bool operator<(const MPInt &other) const { return Compare(other) < 0; }

  inline bool operator==(const MPInt &other) const {
    return Compare(other) == 0;
  }

  inline bool operator!=(const MPInt &other) const {
    return Compare(other) != 0;
  }

  MPInt operator+(const MPInt &operand2) const;
  MPInt operator-(const MPInt &operand2) const;
  MPInt operator*(const MPInt &operand2) const;
  MPInt operator/(const MPInt &operand2) const;
  MPInt operator%(const MPInt &operand2) const;
  MPInt operator<<(size_t operand2) const;
  MPInt operator>>(size_t operand2) const;
  MPInt operator-() const;

  MPInt operator-=(const MPInt &operand2);
  MPInt operator+=(const MPInt &operand2);
  MPInt operator*=(const MPInt &operand2);
  MPInt operator/=(const MPInt &operand2);
  MPInt operator%=(const MPInt &operand2);
  MPInt operator<<=(size_t operand2);
  MPInt operator|=(const MPInt &operand2);

  friend std::ostream &operator<<(std::ostream &os, const MPInt &an_int);

  size_t SizeAllocated() { return n_.alloc * sizeof(mp_digit); }
  size_t SizeUsed() { return n_.used * sizeof(mp_digit); }

  [[nodiscard]] size_t BitCount() const;
  [[nodiscard]] bool IsZero() const;
  void SetZero();
  MPInt &DecrOne() &;
  MPInt &IncrOne() &;
  [[nodiscard]] MPInt DecrOne() &&;
  [[nodiscard]] MPInt IncrOne() &&;

  /* a = -a */
  inline void Negate(MPInt *z) const { MPINT_ENFORCE_OK(mp_neg(&n_, &z->n_)); }
  inline void NegInplace() { MPINT_ENFORCE_OK(mp_neg(&n_, &n_)); }

  [[nodiscard]] inline bool IsNegative() const { return mp_isneg(&n_); }
  [[nodiscard]] inline bool IsPostive() const {
    return !mp_iszero(&n_) && !mp_isneg(&n_);
  }

  [[nodiscard]] inline bool IsOdd() const { return mp_isodd(&n_); }
  [[nodiscard]] inline bool IsEven() const { return mp_iseven(&n_); }

  [[nodiscard]] MPInt Abs() const;

  template <typename T>
  [[nodiscard]] T As() const;

  // compare a to b
  // Returns:
  //  > 0:  this > other
  //  == 0: this == other
  //  < 0:  this < other
  [[nodiscard]] int Compare(const MPInt &other) const;
  // compare a to b
  // Returns:
  //  > 0:  |this| > |other|
  //  == 0: |this| == |other|
  //  < 0:  |this| < |other|
  [[nodiscard]] int CompareAbs(const MPInt &other) const;

  void Serialize(std::string *str) const;
  static bool Deserialize(const std::string &str, MPInt *result);

  [[nodiscard]] std::string ToString() const;
  [[nodiscard]] std::string ToHexString() const;

  /**
   * Generate a random prime
   * +------------+--------------+-----------------+
   * |            |  bit length  |   average time  |
   * +------------+--------------+-----------------+
   * |            |     1024     |       1 min     |
   * | safe prime |--------------+-----------------+
   * |            |     2048     |      20 min     |
   * +------------+--------------+-----------------+
   * @return a bit_size prime whose highest bit always one
   */
  static void RandPrimeOver(size_t bit_size, MPInt *x,
                            PrimeType prime_type = PrimeType::BBS);

  static void RandSafePrimeOver(size_t bit_size, MPInt *x);

  [[nodiscard]] bool IsPrime() const;

  /**
   * (*c) = a * b
   */
  static void Mul(const MPInt &a, const MPInt &b, MPInt *c);

  /**
   * Generate a random number
   * @note
   * The random number generated by libtommath is a multiple of
   * MP_DIGIT_BIT(=60) bit.
   *
   * For example, if the input bit_size = 105, then:
   * > RandomRoundDown
   *     - Generate a 60-bit random number with the highest bit being 1.
   * > RandomRoundUp
   *     - Generate 120-bit random numbers with the highest bit being 1.
   * > RandomExactBits
   *     - Generate an exact bit_size random number, the smb is not guaranteed
   * to be 1.
   * > RandomMonicExactBits
   *     - Generate an exact bit_size random number with the highest bit
   * being 1.
   */
  static void RandomRoundDown(size_t bit_size, MPInt *r);
  static void RandomRoundUp(size_t bit_size, MPInt *r);
  static void RandomExactBits(size_t bit_size, MPInt *r);
  static void RandomMonicExactBits(size_t bit_size, MPInt *r);

  /**
   * select a random r < n
   */
  static void RandomLtN(const MPInt &n, MPInt *r);

  /**
   *  (*d) = (a * b) mod c
   */
  static void MulMod(const MPInt &a, const MPInt &b, const MPInt &mod,
                     MPInt *d);

  // *d = (a**b) mod c
  static void PowMod(const MPInt &a, const MPInt &b, const MPInt &mod,
                     MPInt *d);
  static void Pow(const MPInt &a, uint32_t b, MPInt *c);

  static void Lcm(const MPInt &a, const MPInt &b, MPInt *c);
  static void Gcd(const MPInt &a, const MPInt &b, MPInt *c);
  /* a/b => cb + d == a */
  static void Div(const MPInt &a, const MPInt &b, MPInt *c, MPInt *d);

  /**
   * b = a // 3
   */
  static void Div3(const MPInt &a, MPInt *b);

  /**
   * ac = 1 (mod b)
   * example: a = 3, b = 10000, output c = 6667
   *
   * @note A necessary and sufficient condition for the existence of c is that a
   * and b are coprime. If a and b are not coprime, then c does not exist and an
   * exception is thrown
   */
  static void InvertMod(const MPInt &a, const MPInt &mod, MPInt *c);

  /* c = a mod b, 0 <= c < b  */
  static void Mod(const MPInt &a, const MPInt &mod, MPInt *c);

 protected:
  explicit MPInt(uint64_t value, size_t reserved_bits);

  mp_int n_;

 private:
  [[nodiscard]] std::string ToRadixString(int radix) const;

  friend class MontgomerySpace;
};

// 目前所有算法 Plaintext 等价于 MPInt，所以添加一个别名到此处
// Cleartext --(encoding)--> Plaintext --(encrypt)--> Ciphertext
using Plaintext = MPInt;

}  // namespace heu::lib::algorithms

// clang-format off
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

  template<>
  struct pack<heu::lib::algorithms::MPInt> {
    template<typename Stream>
    msgpack::packer<Stream> &operator()(msgpack::packer<Stream> &object,
        const heu::lib::algorithms::MPInt &mp) const {
      std::string bytes;
      mp.Serialize(&bytes);
      object.pack(bytes);
      return object;
    }
  };

  template<>
  struct convert<heu::lib::algorithms::MPInt> {
    const msgpack::object &operator()(const msgpack::object &object,
        heu::lib::algorithms::MPInt &mp) const {
      if (!heu::lib::algorithms::MPInt::Deserialize(object.as<std::string>(), &mp)) {
        throw msgpack::type_error();
      }
      return object;
    }
  };

}  // namespace adaptor
}  // MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
}  // namespace msgpack
// clang-format on
