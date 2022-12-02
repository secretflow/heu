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

#include "pybind11/pytypes.h"

#include "heu/library/phe/encoding/encoding.h"
#include "heu/pylib/common/py_utils.h"

namespace heu::pylib {

using lib::phe::Plaintext;

// Helper class for python binding
class PyIntegerEncoder {
 public:
  using DefaultPlainT = int64_t;
  static constexpr std::string_view DefaultPyTypeFormat = "l";

  explicit PyIntegerEncoder(lib::phe::SchemaType schema, int64_t scale = 1e6)
      : encoder_(schema, scale) {}
  explicit PyIntegerEncoder(const lib::phe::PlainEncoder &encoder)
      : encoder_(encoder) {}

  [[nodiscard]] yacl::Buffer Serialize() const;

  static PyIntegerEncoder LoadFrom(yacl::ByteContainerView buf);

  // Encode cleartext to plaintext
  template <typename T,
            typename std::enable_if_t<std::is_integral_v<T>, int> = 0>
  [[nodiscard]] Plaintext Encode(T cleartext) const {
    return encoder_.Encode(cleartext);
  }

  template <typename T,
            typename std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
  [[nodiscard]] Plaintext Encode(T cleartext) const {
    // convert float to int, PyIntegerEncoder can only encode integers
    return encoder_.Encode(static_cast<int128_t>(cleartext));
  }

  // NOT thread safe
  [[nodiscard]] Plaintext Encode(const pybind11::int_ &cleartext) const {
    auto [v, overflow] = (PyUtils::PyIntToCppInt128(cleartext));
    YACL_ENFORCE(!overflow,
                 "IntegerEncoder cannot encode numbers larger than 128 bits");

    return encoder_.Encode(v);
  }

  [[nodiscard]] Plaintext Encode(PyObject *cleartext) const {
    YACL_THROW_LOGIC_ERROR(
        "IntegerEncoder can not encode 'PyObject' type element");
  }

  // Decode plaintext to cleartext
  template <typename T>
  [[nodiscard]] typename std::enable_if_t<std::is_integral_v<T>, T> Decode(
      const Plaintext &plaintext) const {
    return encoder_.Decode<T>(plaintext);
  }

  // NOT thread safe
  [[nodiscard]] pybind11::object DecodeAsPyObj(
      const Plaintext &plaintext) const {
    if (plaintext.BitCount() < 64) {  // Up to 63bit regardless of sign bit
      return pybind11::int_(Decode<int64_t>(plaintext));
    }
    return PyUtils::CppInt128ToPyInt(Decode<int128_t>(plaintext));
  }

  [[nodiscard]] std::string ToString() const;

 private:
  lib::phe::PlainEncoder encoder_;
};

struct PyIntegerEncoderParams
    : lib::algorithms::HeObject<PyIntegerEncoderParams> {
  int64_t scale;
  MSGPACK_DEFINE(scale);

  explicit PyIntegerEncoderParams(int64_t scale = 1e6) : scale(scale) {}
  PyIntegerEncoder Instance(lib::phe::SchemaType schema) const {
    return PyIntegerEncoder(schema, scale);
  }

  std::string ToString() const;
};

void BindPyIntegerEncoder(pybind11::module &m);

}  // namespace heu::pylib
