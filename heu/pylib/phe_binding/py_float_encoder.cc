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

#include "heu/pylib/phe_binding/py_float_encoder.h"

namespace heu::pylib {

using lib::phe::Plaintext;

yasl::Buffer PyFloatEncoder::Serialize() const { return encoder_.Serialize(); }

PyFloatEncoder PyFloatEncoder::LoadFrom(yasl::ByteContainerView buf) {
  return PyFloatEncoder(lib::phe::PlainEncoder::LoadFrom(buf));
}

std::string PyFloatEncoder::ToString() const {
  return fmt::format("FloatEncoder(schema={}, scale={})", encoder_.GetSchema(),
                     encoder_.GetScale());
}

std::string PyFloatEncoderParams::ToString() const {
  return fmt::format("FloatEncoderParams(scale={})", scale);
}

void BindPyFloatEncoder(pybind11::module &m) {
  namespace py = ::pybind11;

  py::class_<PyFloatEncoderParams>(m, "FloatEncoderParams")
      .def(py::init<int64_t>(), py::arg("scale") = (int64_t)1e6,
           "parameters for FloatEncoder")
      .def("__str__", &PyFloatEncoderParams::ToString)
      .def("__repr__", &PyFloatEncoderParams::ToString);

  py::class_<PyFloatEncoder>(m, "FloatEncoder")
      .def(py::init<lib::phe::SchemaType, int64_t>(), py::arg("schema"),
           py::arg("scale"))
      .def(py::init<lib::phe::SchemaType>(), py::arg("schema_type"),
           "Create an integer encoder using default scale")
      .def("__str__", &PyFloatEncoder::ToString)
      .def("__repr__", &PyFloatEncoder::ToString)
      .def(PyUtils::PickleSupport<PyFloatEncoder>())
      .def("encode", &PyFloatEncoder::Encode<double>, py::arg("cleartext"),
           "Encode a float number into plaintext")
      .def(
          "encode",
          [](const PyFloatEncoder &pe, const py::int_ &p) {
            return pe.Encode(p);
          },
          py::arg("cleartext"), "Encode an int128 number into plaintext")
      .def("decode", &PyFloatEncoder::Decode<double>, py::arg("plaintext"),
           "Decode plaintext to float number")
      .doc() =
      "Encode cleartext into plaintext.\n\n"
      "The cleartext can be a floating point number";
}

}  // namespace heu::pylib
