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
class PyBatchEncoder {
 public:
  using DefaultPlainT = int64_t;
  constexpr static std::string_view DefaultPyTypeFormat = "l";

  explicit PyBatchEncoder(lib::phe::SchemaType schema,
                          size_t batch_encoding_padding = 32)
      : encoder_(schema, batch_encoding_padding) {}
  explicit PyBatchEncoder(const lib::phe::BatchEncoder &encoder)
      : encoder_(encoder) {}

  [[nodiscard]] yasl::Buffer Serialize() const;

  static PyBatchEncoder LoadFrom(yasl::ByteContainerView buf);

  template <typename T,
            typename std::enable_if_t<std::is_integral_v<T>, int> = 0>
  Plaintext Encode(T first, T second) const {
    return encoder_.Encode<int64_t>(first, second);
  }

  template <typename T,
            typename std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
  Plaintext Encode(T first, T second) const {
    YASL_THROW_LOGIC_ERROR("BatchEncoder can not encode float element");
  }

  [[nodiscard]] Plaintext Encode(PyObject *first, PyObject *second) const {
    YASL_THROW_LOGIC_ERROR(
        "BatchEncoder can not encode 'PyObject' type element");
  }

  template <size_t index>
  [[nodiscard]] int64_t Decode(const Plaintext &plaintext) const {
    return encoder_.Decode<int64_t, index>(plaintext);
  }

  lib::phe::SchemaType GetSchema() const { return encoder_.GetSchema(); }
  size_t GetPaddingSize() const { return encoder_.GetPaddingSize(); }
  [[nodiscard]] std::string ToString() const;

 private:
  lib::phe::BatchEncoder encoder_;
};

struct PyBatchEncoderParams : lib::algorithms::HeObject<PyBatchEncoderParams> {
  int64_t padding_size;
  MSGPACK_DEFINE(padding_size);

  explicit PyBatchEncoderParams(int64_t padding_size = 1e6)
      : padding_size(padding_size) {}
  PyBatchEncoder Instance(lib::phe::SchemaType schema) const {
    return PyBatchEncoder(schema, padding_size);
  }

  [[nodiscard]] std::string ToString() const;
};

void BindPyBatchEncoder(pybind11::module &m);

}  // namespace heu::pylib
