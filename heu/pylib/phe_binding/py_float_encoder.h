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
class PyFloatEncoder {
 public:
  using DefaultPlainT = double;
  constexpr static std::string_view DefaultPyTypeFormat = "d";

  explicit PyFloatEncoder(lib::phe::SchemaType schema, int64_t scale = 1e6)
      : encoder_(schema, scale) {}
  explicit PyFloatEncoder(const lib::phe::PlainEncoder &encoder)
      : encoder_(encoder) {}

  [[nodiscard]] yasl::Buffer Serialize() const;

  static PyFloatEncoder LoadFrom(yasl::ByteContainerView buf);

  template <typename T,
            typename std::enable_if_t<std::is_arithmetic_v<T>, int> = 0>
  [[nodiscard]] Plaintext Encode(T cleartext) const {
    return encoder_.template Encode(cleartext);
  }

  // NOT thread safe
  [[nodiscard]] Plaintext Encode(const pybind11::int_ &cleartext) const {
    auto [v, overflow] = (PyUtils::PyIntToCppInt128(cleartext));
    YASL_ENFORCE(!overflow,
                 "FloatEncoder cannot encode int numbers larger than 128 bits");

    return encoder_.Encode(v);
  }

  [[nodiscard]] Plaintext Encode(PyObject *cleartext) const {
    YASL_THROW_LOGIC_ERROR(
        "FloatEncoder can not encode 'PyObject' type element");
  }

  // Decode plaintext to cleartext
  template <typename T>
  [[nodiscard]] typename std::enable_if_t<std::is_floating_point_v<T>, T>
  Decode(const Plaintext &plaintext) const {
    return encoder_.Decode<T>(plaintext);
  }

  // NOT thread safe
  [[nodiscard]] pybind11::object DecodeAsPyObj(
      const Plaintext &plaintext) const {
    return pybind11::float_(encoder_.Decode<double>(plaintext));
  }

  [[nodiscard]] std::string ToString() const;

 private:
  lib::phe::PlainEncoder encoder_;
};

struct PyFloatEncoderParams : lib::algorithms::HeObject<PyFloatEncoderParams> {
  int64_t scale;
  MSGPACK_DEFINE(scale);

  explicit PyFloatEncoderParams(int64_t scale = 1e6) : scale(scale) {}
  PyFloatEncoder Instance(lib::phe::SchemaType schema) const {
    return PyFloatEncoder(schema, scale);
  }

  [[nodiscard]] std::string ToString() const;
};

void BindPyFloatEncoder(pybind11::module &m);

}  // namespace heu::pylib
