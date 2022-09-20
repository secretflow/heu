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

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::phe {

class BatchEncoder : public algorithms::HeObject<BatchEncoder> {
 public:
  // During batch encoding, if the lower digits overflow, the upper digits will
  // be affected. The default parameter 32 bit padding supports approximately 2
  // billion addition operations
  explicit BatchEncoder(size_t batch_encoding_padding = 32)
      : encoding_padding_(batch_encoding_padding) {}

  // todo: When the project is migrated to C++20, it can be replaced with
  // concept.
  //
  // template <typename T> concept SignedIntegralType =
  //    std::is_signed<T>::value && std::is_integral<T>::value;
  //
  // template <typename T>
  // concept UnsignedIntegralType =
  //    std::is_unsigned<T>::value && std::is_integral<T>::value;

  // Encoding signed number，supports int8 ~ int64
  template <typename T,
            typename std::enable_if_t<
                std::is_signed_v<T> && std::is_integral_v<T>, int> = 0>
  algorithms::Plaintext Encode(T first, T second) const {
    typedef typename std::make_unsigned<T>::type unsigned_t;
    return Encode<unsigned_t>(*reinterpret_cast<unsigned_t *>(&first),
                              *reinterpret_cast<unsigned_t *>(&second));
  }

  // Encoding unsigned numbers，supports uint8 ~ uint64
  template <typename T,
            typename std::enable_if_t<
                std::is_unsigned_v<T> && std::is_integral_v<T>, int> = 0>
  algorithms::Plaintext Encode(T first, T second) const {
    algorithms::Plaintext pt(second);
    pt <<= sizeof(second) * CHAR_BIT + encoding_padding_;
    pt |= algorithms::MPInt(first);
    return pt;
  }

  // Decode element.
  // return 0 if index is greater or equal to the number encoded in plaintext
  template <typename T, size_t index>
  typename std::enable_if_t<std::is_integral_v<T>, T> Decode(
      const algorithms::Plaintext &plaintext) const {
    static_assert(index < 2,
                  "You cannot get more than two elements from one plaintext");
    algorithms::Plaintext pt =
        plaintext >> index * (sizeof(T) * CHAR_BIT + encoding_padding_);
    return pt.As<T>();
  }

  MSGPACK_DEFINE(encoding_padding_);
  [[nodiscard]] std::string ToString() const override {
    return fmt::format("BatchEncoder(padding={}, max_batch=2)",
                       encoding_padding_);
  }

 private:
  size_t encoding_padding_;
};

}  // namespace heu::lib::phe
