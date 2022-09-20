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

// Helper class for python binding
class PyIntegerEncoder : public lib::algorithms::HeObject<PyIntegerEncoder> {
 public:
  using DefaultPlainT = int64_t;
  static constexpr std::string_view DefaultPyTypeFormat = "l";

  explicit PyIntegerEncoder(int64_t scale = 1e6) : encoder_(scale) {}

  // Encode cleartext to plaintext
  template <typename T,
            typename std::enable_if_t<std::is_integral_v<T>, int> = 0>
  [[nodiscard]] lib::algorithms::Plaintext Encode(T cleartext) const {
    return encoder_.Encode(cleartext);
  }

  template <typename T,
            typename std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
  [[nodiscard]] lib::algorithms::Plaintext Encode(T cleartext) const {
    return encoder_.Encode(static_cast<int128_t>(cleartext));
  }

  // NOT thread safe
  [[nodiscard]] lib::algorithms::Plaintext Encode(
      const pybind11::int_ &cleartext) const {
    auto [v, overflow] = (PyUtils::PyIntToCppInt128(cleartext));
    YASL_ENFORCE(!overflow,
                 "IntegerEncoder cannot encode numbers larger than 128 bits");

    return encoder_.Encode(v);
  }

  [[nodiscard]] lib::algorithms::Plaintext Encode(PyObject *cleartext) const {
    YASL_THROW_LOGIC_ERROR(
        "IntegerEncoder can not encode 'PyObject' type element");
  }

  // Decode plaintext to cleartext
  template <typename T>
  [[nodiscard]] typename std::enable_if_t<std::is_integral_v<T>, T> Decode(
      const lib::algorithms::Plaintext &plaintext) const {
    return encoder_.Decode<T>(plaintext);
  }

  // NOT thread safe
  [[nodiscard]] pybind11::object DecodeAsPyObj(
      const lib::algorithms::Plaintext &plaintext) const {
    if (plaintext.BitCount() < 64) {  // Up to 63bit regardless of sign bit
      return pybind11::int_(Decode<int64_t>(plaintext));
    }
    return PyUtils::CppInt128ToPyInt(Decode<int128_t>(plaintext));
  }

  [[nodiscard]] std::string ToString() const override;
  MSGPACK_DEFINE(encoder_);

 private:
  lib::phe::PlainEncoder encoder_;
};

// Helper class for python binding
class PyFloatEncoder : public lib::algorithms::HeObject<PyFloatEncoder> {
 public:
  using DefaultPlainT = double;
  constexpr static std::string_view DefaultPyTypeFormat = "d";

  explicit PyFloatEncoder(int64_t scale = 1e6) : encoder_(scale) {}

  template <typename T,
            typename std::enable_if_t<std::is_arithmetic_v<T>, int> = 0>
  [[nodiscard]] lib::algorithms::Plaintext Encode(T cleartext) const {
    return encoder_.template Encode(cleartext);
  }

  // NOT thread safe
  [[nodiscard]] lib::algorithms::Plaintext Encode(
      const pybind11::int_ &cleartext) const {
    auto [v, overflow] = (PyUtils::PyIntToCppInt128(cleartext));
    YASL_ENFORCE(!overflow,
                 "FloatEncoder cannot encode int numbers larger than 128 bits");

    return encoder_.Encode(v);
  }

  [[nodiscard]] lib::algorithms::Plaintext Encode(PyObject *cleartext) const {
    YASL_THROW_LOGIC_ERROR(
        "FloatEncoder can not encode 'PyObject' type element");
  }

  // Decode plaintext to cleartext
  template <typename T>
  [[nodiscard]] typename std::enable_if_t<std::is_floating_point_v<T>, T>
  Decode(const lib::algorithms::Plaintext &plaintext) const {
    return encoder_.Decode<T>(plaintext);
  }

  // NOT thread safe
  [[nodiscard]] pybind11::object DecodeAsPyObj(
      const lib::algorithms::Plaintext &plaintext) const {
    return pybind11::float_(encoder_.Decode<double>(plaintext));
  }

  [[nodiscard]] std::string ToString() const override;
  MSGPACK_DEFINE(encoder_);

 private:
  lib::phe::PlainEncoder encoder_;
};

// Helper class for python binding
class PyBigintEncoder : public lib::algorithms::HeObject<PyBigintEncoder> {
 public:
  using DefaultPlainT = PyObject *;
  constexpr static std::string_view DefaultPyTypeFormat = "O";

  template <typename T,
            typename std::enable_if_t<std::is_arithmetic_v<T>, int> = 0>
  [[nodiscard]] lib::algorithms::Plaintext Encode(T cleartext) const {
    return lib::algorithms::Plaintext(cleartext);
  }

  // NOT thread safe
  [[nodiscard]] lib::algorithms::Plaintext Encode(PyObject *cleartext) const {
    return PyUtils::PyIntToPlaintext(
        pybind11::reinterpret_borrow<pybind11::int_>(cleartext));
  }

  // NOT thread safe
  [[nodiscard]] lib::algorithms::Plaintext Encode(
      const pybind11::int_ &cleartext) const {
    return PyUtils::PyIntToPlaintext(cleartext);
  }

  // warning: NOT thread safe. (Because python interpreter is not thread safe)
  // warning: This function returns a raw pointer. Please make sure the memory
  // will be freed in python side.
  template <typename T,
            typename std::enable_if_t<std::is_same_v<T, PyObject *>, int> = 0>
  [[nodiscard]] T Decode(const lib::algorithms::Plaintext &plaintext) const {
    return PyUtils::PlaintextToPyInt(plaintext).release().ptr();
  }

  // NOT thread safe
  [[nodiscard]] pybind11::object DecodeAsPyObj(
      const lib::algorithms::Plaintext &plaintext) const {
    return PyUtils::PlaintextToPyInt(plaintext);
  }

  [[nodiscard]] std::string ToString() const override;

  MSGPACK_DEFINE();
};

// Helper class for python binding
class PyBatchEncoder : public lib::algorithms::HeObject<PyBatchEncoder> {
 public:
  using DefaultPlainT = int64_t;
  constexpr static std::string_view DefaultPyTypeFormat = "l";

  explicit PyBatchEncoder(size_t batch_encoding_padding = 32)
      : encoder_(batch_encoding_padding) {}

  template <typename T,
            typename std::enable_if_t<std::is_integral_v<T>, int> = 0>
  lib::algorithms::Plaintext Encode(T first, T second) const {
    return encoder_.Encode<int64_t>(first, second);
  }

  template <typename T,
            typename std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
  lib::algorithms::Plaintext Encode(T first, T second) const {
    YASL_THROW_LOGIC_ERROR("BatchEncoder can not encode float element");
  }

  [[nodiscard]] lib::algorithms::Plaintext Encode(PyObject *first,
                                                  PyObject *second) const {
    YASL_THROW_LOGIC_ERROR(
        "BatchEncoder can not encode 'PyObject' type element");
  }

  template <size_t index>
  [[nodiscard]] int64_t Decode(
      const lib::algorithms::Plaintext &plaintext) const {
    return encoder_.Decode<int64_t, index>(plaintext);
  }

  [[nodiscard]] std::string ToString() const override;
  MSGPACK_DEFINE(encoder_);

 private:
  lib::phe::BatchEncoder encoder_;
};

}  // namespace heu::pylib
