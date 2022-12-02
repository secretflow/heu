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

#include "heu/pylib/phe_binding/py_integer_encoder.h"

namespace heu::pylib {

using lib::phe::Plaintext;

yacl::Buffer PyIntegerEncoder::Serialize() const {
  return encoder_.Serialize();
}

PyIntegerEncoder PyIntegerEncoder::LoadFrom(yacl::ByteContainerView buf) {
  return PyIntegerEncoder(lib::phe::PlainEncoder::LoadFrom(buf));
}

std::string PyIntegerEncoder::ToString() const {
  return fmt::format("IntegerEncoder(schema={}, scale={})",
                     encoder_.GetSchema(), encoder_.GetScale());
}

std::string PyIntegerEncoderParams::ToString() const {
  return fmt::format("IntegerEncoderParams(scale={})", scale);
}

void BindPyIntegerEncoder(pybind11::module &m) {
  namespace py = ::pybind11;

  py::class_<PyIntegerEncoderParams>(m, "IntegerEncoderParams")
      .def(py::init<int64_t>(), py::arg("scale") = (int64_t)1e6,
           "parameters for IntegerEncoder")
      .def("__str__", &PyIntegerEncoderParams::ToString)
      .def("__repr__", &PyIntegerEncoderParams::ToString)
      .def(PyUtils::PickleSupport<PyIntegerEncoderParams>())
      .def("instance", &PyIntegerEncoderParams::Instance,
           "Create IntegerEncoder instance");

  py::class_<PyIntegerEncoder>(m, "IntegerEncoder")
      .def(py::init<lib::phe::SchemaType, int64_t>(), py::arg("schema"),
           py::arg("scale"))
      .def(py::init<lib::phe::SchemaType>(), py::arg("schema_type"),
           "Create an integer encoder using default scale")
      .def("__str__", &PyIntegerEncoder::ToString)
      .def("__repr__", &PyIntegerEncoder::ToString)
      .def(PyUtils::PickleSupport<PyIntegerEncoder>())
      .def(
          "encode",
          [](const PyIntegerEncoder &pe, const py::int_ &p) {
            return pe.Encode(p);
          },
          py::arg("cleartext"), "Encode an int128 number into plaintext")
      .def("encode",
           py::overload_cast<double>(&PyIntegerEncoder::Encode<double>,
                                     py::const_),
           "Encode the integer part of a floating point number. "
           "(discarding the fractional part)")
      .def("decode", &PyIntegerEncoder::DecodeAsPyObj, py::arg("plaintext"),
           "Decode plaintext to int128 number")
      .doc() =
      "Encode cleartext into plaintext.\n\n"
      "The cleartext must be an integer. If the cleartext is a floating-point "
      "number, the fractional part will be discarded.";
}

}  // namespace heu::pylib
