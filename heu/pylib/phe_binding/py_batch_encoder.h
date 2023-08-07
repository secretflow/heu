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

// Base class of PyBatch{Integer/Float}Encoder
template <typename RealEncoderT, typename CleartextT>
class PyBatchEncoder {
 public:
  using DefaultPlainT = CleartextT;
  constexpr static std::string_view DefaultPyTypeFormat =
      std::is_floating_point_v<CleartextT> ? "d" : "l";

  virtual ~PyBatchEncoder() = default;

  [[nodiscard]] yacl::Buffer Serialize() const { return encoder_.Serialize(); }

  static RealEncoderT LoadFrom(yacl::ByteContainerView buf) {
    return RealEncoderT(lib::phe::BatchEncoder::LoadFrom(buf));
  }

  Plaintext Encode(CleartextT first, CleartextT second) const {
    return encoder_.Encode(first, second);
  }

  [[nodiscard]] Plaintext Encode(PyObject *first, PyObject *second) const {
    YACL_THROW_LOGIC_ERROR(
        "BatchFloatEncoder can not encode 'PyObject' type element");
  }

  template <size_t index>
  [[nodiscard]] CleartextT Decode(const Plaintext &plaintext) const {
    return encoder_.Decode<CleartextT, index>(plaintext);
  }

  lib::phe::SchemaType GetSchema() const { return encoder_.GetSchema(); }

  size_t GetScale() const { return encoder_.GetScale(); }

  size_t GetPaddingBits() const { return encoder_.GetPaddingBits(); }

  [[nodiscard]] std::string ToString() const {
    return fmt::format("{}(schema={}, scale={}, padding_bits={})",
                       pybind11::type_id<RealEncoderT>(), GetSchema(),
                       GetScale(), GetPaddingBits());
  }

 protected:
  explicit PyBatchEncoder(lib::phe::SchemaType schema, int64_t scale,
                          size_t padding_bits = 32)
      : encoder_(schema, scale, padding_bits) {}

  explicit PyBatchEncoder(const lib::phe::BatchEncoder &encoder)
      : encoder_(encoder) {}

  lib::phe::BatchEncoder encoder_;
};

// Helper class for python binding
class PyBatchIntegerEncoder
    : public PyBatchEncoder<PyBatchIntegerEncoder, int64_t> {
 public:
  explicit PyBatchIntegerEncoder(lib::phe::SchemaType schema, int64_t scale = 1,
                                 size_t padding_bits = 32)
      : PyBatchEncoder(schema, scale, padding_bits) {}

  using PyBatchEncoder<PyBatchIntegerEncoder, int64_t>::PyBatchEncoder;
};

// Helper class for python binding
class PyBatchFloatEncoder : public PyBatchEncoder<PyBatchFloatEncoder, double> {
 public:
  explicit PyBatchFloatEncoder(lib::phe::SchemaType schema, int64_t scale = 1e6,
                               size_t padding_bits = 32)
      : PyBatchEncoder(schema, scale, padding_bits) {}

  using PyBatchEncoder<PyBatchFloatEncoder, double>::PyBatchEncoder;
};

struct PyBatchIntegerEncoderParams
    : lib::algorithms::HeObject<PyBatchIntegerEncoderParams> {
  int64_t scale = 1;
  size_t padding_bits = 32;
  MSGPACK_DEFINE(scale, padding_bits);

  explicit PyBatchIntegerEncoderParams(int64_t scale = 1,
                                       size_t padding_bits = 32)
      : scale(scale), padding_bits(padding_bits) {}

  PyBatchIntegerEncoder Instance(lib::phe::SchemaType schema) const {
    return PyBatchIntegerEncoder(schema, scale, padding_bits);
  }

  [[nodiscard]] std::string ToString() const;
};

struct PyBatchFloatEncoderParams
    : lib::algorithms::HeObject<PyBatchFloatEncoderParams> {
  int64_t scale = 1;
  size_t padding_bits = 32;
  MSGPACK_DEFINE(scale, padding_bits);

  explicit PyBatchFloatEncoderParams(int64_t scale = 1e6,
                                     size_t padding_bits = 32)
      : scale(scale), padding_bits(padding_bits) {}

  PyBatchFloatEncoder Instance(lib::phe::SchemaType schema) const {
    return PyBatchFloatEncoder(schema, scale, padding_bits);
  }

  [[nodiscard]] std::string ToString() const;
};

void BindPyBatchEncoder(pybind11::module &m);

}  // namespace heu::pylib
