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

#include "heu/pylib/phe_binding/py_bigint_encoder.h"

namespace heu::pylib {

using lib::phe::Plaintext;

yasl::Buffer PyBigintEncoder::Serialize() const {
  msgpack::sbuffer buf;
  msgpack::pack(buf, schema_type_);
  return {buf.data(), buf.size()};
}

PyBigintEncoder PyBigintEncoder::LoadFrom(yasl::ByteContainerView buf) {
  auto msg =
      msgpack::unpack(reinterpret_cast<const char *>(buf.data()), buf.size());
  msgpack::object obj = msg.get();
  lib::phe::SchemaType st;
  obj.convert(st);
  return PyBigintEncoder(st);
}

std::string PyBigintEncoder::ToString() const {
  return fmt::format("BigintEncoder(schema={})", schema_type_);
}

std::string PyBigintEncoderParams::ToString() const {
  return fmt::format("BigintEncoderParams()");
}

void BindPyBigintEncoder(pybind11::module &m) {
  namespace py = ::pybind11;

  py::class_<PyBigintEncoderParams>(m, "BigintEncoderParams")
      .def(py::init<>(), "parameters for BigintEncoder")
      .def("__str__", &PyBigintEncoderParams::ToString)
      .def("__repr__", &PyBigintEncoderParams::ToString);

  // PyBigintDecoder does not depend on the schema_type parameter, so sometimes
  // PyBigintDecoder can be used as the default parameter of functions for
  // convenience
  py::class_<PyBigintDecoder>(m, "BigintDecoder")
      .def(py::init<>(), "create BigintDecoder instance")
      .def("__str__", [](const PyBigintDecoder &) { return "BigintDecoder()"; })
      .def("__repr__",
           [](const PyBigintDecoder &) { return "BigintDecoder()"; })
      .def("decode", &PyBigintEncoder::DecodeAsPyObj, py::arg("plaintext"),
           "Decode plaintext to python int number");

  py::class_<PyBigintEncoder, PyBigintDecoder>(m, "BigintEncoder")
      .def(py::init<lib::phe::SchemaType>(), py::arg("schema"),
           "Create a bigint encoder")
      .def("__str__", &PyBigintEncoder::ToString)
      .def("__repr__", &PyBigintEncoder::ToString)
      .def(PyUtils::PickleSupport<PyBigintEncoder>())
      .def(
          "encode",
          [](const PyBigintEncoder &pe, const py::int_ &p) {
            return pe.Encode(p);
          },
          py::arg("cleartext"), "Encode python int number into plaintext")
      .doc() =
      "Encode cleartext into plaintext.\n\n"
      "BigintEncoder supports arbitrary precision integers";
}

}  // namespace heu::pylib
