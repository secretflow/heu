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

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::phe {

namespace {
// clang-format off
template <class> struct next_size;
template <class T> using next_size_t = typename next_size<T>::type;
template <class T> struct tag { using type = T; };

template <> struct next_size<int8_t> : tag<int16_t> {};
template <> struct next_size<int16_t> : tag<int32_t> {};
template <> struct next_size<int32_t> : tag<int64_t> {};
template <> struct next_size<int64_t> : tag<int128_t> {};
template <> struct next_size<int128_t> : tag<int128_t> {};

template <> struct next_size<uint8_t> : tag<uint16_t> {};
template <> struct next_size<uint16_t> : tag<uint32_t> {};
template <> struct next_size<uint32_t> : tag<uint64_t> {};
template <> struct next_size<uint64_t> : tag<uint128_t> {};
template <> struct next_size<uint128_t> : tag<uint128_t> {};

template <> struct next_size<float> : tag<double> {};
template <> struct next_size<double> : tag<double> {};
// clang-format on
}  // namespace

class PlainEncoder : public algorithms::HeObject<PlainEncoder> {
 public:
  explicit PlainEncoder(int64_t scale = 1e6) : scale_(scale) {}

  // Encode cleartext to plaintext
  template <typename T,
            typename std::enable_if_t<std::is_arithmetic_v<T>, int> = 0>
  [[nodiscard]] algorithms::Plaintext Encode(T cleartext) const {
    return algorithms::Plaintext(static_cast<next_size_t<T>>(cleartext) *
                                 scale_);
  }

  // Decode plaintext to cleartext
  template <typename T>
  [[nodiscard]] typename std::enable_if_t<std::is_arithmetic_v<T>, T> Decode(
      const algorithms::Plaintext &plaintext) const {
    return static_cast<T>(plaintext.template As<next_size_t<T>>() / scale_);
  }

  MSGPACK_DEFINE(scale_);

  [[nodiscard]] int64_t GetScale() const { return scale_; }

  [[nodiscard]] std::string ToString() const override {
    return fmt::format("PlainEncoder(scale={})", scale_);
  }

 private:
  int_fast64_t scale_;
};

}  // namespace heu::lib::phe
