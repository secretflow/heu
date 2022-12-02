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

class PyBigintDecoder {
 public:
  using DefaultPlainT = PyObject *;
  constexpr static std::string_view DefaultPyTypeFormat = "O";

  // warning: NOT thread safe. (Because python interpreter is not thread safe)
  // warning: This function returns a raw pointer. Please make sure the memory
  // will be freed in python side.
  template <typename T,
            typename std::enable_if_t<std::is_same_v<T, PyObject *>, int> = 0>
  [[nodiscard]] T Decode(const Plaintext &plaintext) const {
    return PyUtils::PlaintextToPyInt(plaintext).release().ptr();
  }

  // NOT thread safe
  [[nodiscard]] pybind11::object DecodeAsPyObj(
      const Plaintext &plaintext) const {
    return PyUtils::PlaintextToPyInt(plaintext);
  }
};

// Helper class for python binding
class PyBigintEncoder : public PyBigintDecoder {
 public:
  explicit PyBigintEncoder(lib::phe::SchemaType schema_type)
      : schema_type_(schema_type) {}

  [[nodiscard]] yacl::Buffer Serialize() const;

  static PyBigintEncoder LoadFrom(yacl::ByteContainerView buf);

  template <typename T,
            typename std::enable_if_t<std::is_arithmetic_v<T>, int> = 0>
  [[nodiscard]] Plaintext Encode(T cleartext) const {
    return Plaintext(schema_type_, cleartext);
  }

  // NOT thread safe
  [[nodiscard]] Plaintext Encode(PyObject *cleartext) const {
    return PyUtils::PyIntToPlaintext(
        schema_type_, pybind11::reinterpret_borrow<pybind11::int_>(cleartext));
  }

  // NOT thread safe
  [[nodiscard]] Plaintext Encode(const pybind11::int_ &cleartext) const {
    return PyUtils::PyIntToPlaintext(schema_type_, cleartext);
  }

  [[nodiscard]] std::string ToString() const;

  MSGPACK_DEFINE(schema_type_);

 private:
  lib::phe::SchemaType schema_type_;
};

struct PyBigintEncoderParams
    : lib::algorithms::HeObject<PyBigintEncoderParams> {
  MSGPACK_DEFINE();

  PyBigintEncoder Instance(lib::phe::SchemaType schema) const {
    return PyBigintEncoder(schema);
  }

  [[nodiscard]] std::string ToString() const;
};

void BindPyBigintEncoder(pybind11::module &m);

}  // namespace heu::pylib
