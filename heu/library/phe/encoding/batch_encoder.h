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

#include <type_traits>

#include "fmt/compile.h"
#include "yacl/base/exception.h"

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"
#include "heu/library/phe/base/plaintext.h"

namespace heu::lib::phe {

class BatchEncoder : public algorithms::HeObject<BatchEncoder> {
 public:
  // During batch encoding, if the lower digits overflow, the upper digits will
  // be affected. The default parameter 32 bit padding supports approximately 2
  // billion addition operations
  explicit BatchEncoder(SchemaType schema, int64_t scale = 1,
                        size_t padding_bits = 32)
      : schema_(schema), scale_(scale), padding_bits_(padding_bits) {}

  static BatchEncoder LoadFrom(yacl::ByteContainerView buf) {
    return BatchEncoder(buf);
  }

  // todo: When the project is migrated to C++20, it can be replaced with
  // concept.
  //
  // template <typename T> concept SignedIntegralType =
  //    std::is_signed<T>::value && std::is_integral<T>::value;
  //
  // template <typename T>
  // concept UnsignedIntegralType =
  //    std::is_unsigned<T>::value && std::is_integral<T>::value;

  // Encoding signed number，supports int8 ~ int128
  // Be careful of overflow
  template <typename T,
            typename std::enable_if_t<
                std::is_signed_v<T> && std::is_integral_v<T>, int> = 0>
  Plaintext Encode(T first, T second) const {
    typedef typename std::make_unsigned<T>::type unsigned_t;
    T n1 = first * static_cast<T>(scale_);
    T n2 = second * static_cast<T>(scale_);
    // get raw buffer (means 2's complement code) and encode it
    return DoEncode<unsigned_t>(*reinterpret_cast<unsigned_t *>(&n1),
                                *reinterpret_cast<unsigned_t *>(&n2));
  }

  // Encoding unsigned numbers，supports uint8 ~ uint128
  // Be careful of overflow
  template <typename T,
            typename std::enable_if_t<
                std::is_unsigned_v<T> && std::is_integral_v<T>, int> = 0>
  Plaintext Encode(T first, T second) const {
    return DoEncode(static_cast<T>(first * static_cast<T>(scale_)),
                    static_cast<T>(second * static_cast<T>(scale_)));
  }

  // Encoding float or double variables
  // Be careful of overflow
  template <typename T,
            typename std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
  Plaintext Encode(T first, T second) const {
    auto n1 = static_cast<int64_t>(static_cast<double>(first) * scale_);
    auto n2 = static_cast<int64_t>(static_cast<double>(second) * scale_);
    // same with encode an int64 number
    return DoEncode<uint64_t>(*reinterpret_cast<uint64_t *>(&n1),
                              *reinterpret_cast<uint64_t *>(&n2));
  }

  // Decode element. supports (u)int8 ~ (u)int128
  // return 0 if index is greater or equal to the number encoded in plaintext
  template <typename T, size_t index>
  typename std::enable_if_t<std::is_integral_v<T>, T> Decode(
      const Plaintext &plaintext) const {
    static_assert(index < 2,
                  "You cannot get more than two elements from one plaintext");
    Plaintext pt = plaintext >> index * (sizeof(T) * CHAR_BIT + padding_bits_);
    // The T in GetValue<> must exactly same with T in Encode<>, otherwise we
    // cannot get the right 2's complement code when result is negative.
    return pt.template GetValue<T>() / static_cast<T>(scale_);
  }

  template <typename T, size_t index>
  typename std::enable_if_t<std::is_floating_point_v<T>, T> Decode(
      const Plaintext &plaintext) const {
    static_assert(index < 2,
                  "You cannot get more than two elements from one plaintext");
    Plaintext pt =
        plaintext >> index * (sizeof(int64_t) * CHAR_BIT + padding_bits_);
    return pt.template GetValue<int64_t>() / static_cast<T>(scale_);
  }

  MSGPACK_DEFINE(schema_, scale_, padding_bits_);

  SchemaType GetSchema() const { return schema_; }

  int64_t GetScale() const { return scale_; }

  size_t GetPaddingBits() const { return padding_bits_; }

  [[nodiscard]] std::string ToString() const override {
    return fmt::format(
        "BatchEncoder(schema={}, scale={}, padding_bits={}, max_batch=2)",
        schema_, scale_, padding_bits_);
  }

 private:
  explicit BatchEncoder(yacl::ByteContainerView buf) { Deserialize(buf); }

  template <typename T,
            typename std::enable_if_t<
                std::is_unsigned_v<T> && std::is_integral_v<T>, int> = 0>
  Plaintext DoEncode(T first, T second) const {
    Plaintext pt(schema_, second);
    pt <<= sizeof(T) * CHAR_BIT + padding_bits_;
    pt |= Plaintext(schema_, first);
    return pt;
  }

  SchemaType schema_{};
  int64_t scale_ = 0;
  size_t padding_bits_ = 0;
};

}  // namespace heu::lib::phe
