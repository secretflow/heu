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

#include "heu/pylib/phe_binding//py_batch_encoder.h"

namespace heu::pylib {

using lib::phe::Plaintext;

std::string PyBatchIntegerEncoderParams::ToString() const {
  return fmt::format("BatchIntegerEncoderParams(scale={}, padding_bits={})",
                     scale, padding_bits);
}
std::string PyBatchFloatEncoderParams::ToString() const {
  return fmt::format("BatchFloatEncoderParams(scale={}, padding_bits={})",
                     scale, padding_bits);
}

void BindPyBatchEncoder(pybind11::module &m) {
  namespace py = ::pybind11;

  py::class_<PyBatchIntegerEncoderParams>(m, "BatchIntegerEncoderParams")
      .def(py::init<size_t, size_t>(), py::arg("scale") = 1,
           py::arg("padding_bits") = 32, "Init BatchIntegerEncoderParams")
      .def("__str__", &PyBatchIntegerEncoderParams::ToString)
      .def("__repr__", &PyBatchIntegerEncoderParams::ToString)
      .def(PyUtils::PickleSupport<PyBatchIntegerEncoderParams>())
      .def("instance", &PyBatchIntegerEncoderParams::Instance,
           py::arg("schema"), "Create BatchIntegerEncoder instance")
      .doc() = "Store parameters for BatchIntegerEncoder";

  py::class_<PyBatchFloatEncoderParams>(m, "BatchFloatEncoderParams")
      .def(py::init<size_t, size_t>(), py::arg("scale") = (int64_t)1e6,
           py::arg("padding_bits") = 32, "Init PyBatchFloatEncoderParams")
      .def("__str__", &PyBatchFloatEncoderParams::ToString)
      .def("__repr__", &PyBatchFloatEncoderParams::ToString)
      .def(PyUtils::PickleSupport<PyBatchFloatEncoderParams>())
      .def("instance", &PyBatchFloatEncoderParams::Instance, py::arg("schema"),
           "Create BatchFloatEncoder instance")
      .doc() = "Store parameters for BatchFloatEncoder";

  py::class_<PyBatchIntegerEncoder>(m, "BatchIntegerEncoder")
      .def(py::init<lib::phe::SchemaType, int64_t, size_t>(), py::arg("schema"),
           py::arg("scale") = 1, py::arg("padding_bits") = 32)
      .def("__str__", &PyBatchIntegerEncoder::ToString)
      .def("__repr__", &PyBatchIntegerEncoder::ToString)
      .def(PyUtils::PickleSupport<PyBatchIntegerEncoder>())
      .def(
          "encode",
          [](const PyBatchIntegerEncoder &bn, int64_t i1, int64_t i2) {
            return bn.Encode(i1, i2);
          },
          py::arg("cleartext_1"), py::arg("cleartext_2"),
          "Encode two int64 cleartexts into one plaintext")
      .def(
          "decode",
          [](const PyBatchIntegerEncoder &bn, const lib::phe::Plaintext &mp) {
            return py::make_tuple(bn.Decode<0>(mp), bn.Decode<1>(mp));
          },
          py::arg("plaintext"), "Decode plaintext and return two cleartexts")
      .doc() = "BatchIntegerEncoder can encode two integers into one plaintext";

  py::class_<PyBatchFloatEncoder>(m, "BatchFloatEncoder")
      .def(py::init<lib::phe::SchemaType, int64_t, size_t>(), py::arg("schema"),
           py::arg("scale") = (int64_t)1e6, py::arg("padding_bits") = 32,
           "Create a BatchFloatEncoder\n\nArgs:\n"
           "  scale (int): Homomorphic encryption only supports integers "
           "internally, so floating-point numbers will be converted to "
           "integers by multiplied a scale. Please note that the encoded "
           "number cannot exceed 64 bits, otherwise it will overflow.\n"
           "  padding_bits (int): The gap between two numbers, if the gap is "
           "too small, the low bit number will pollute the high bit number, "
           "resulting in wrong results.")
      .def("__str__", &PyBatchFloatEncoder::ToString)
      .def("__repr__", &PyBatchFloatEncoder::ToString)
      .def(PyUtils::PickleSupport<PyBatchFloatEncoder>())
      .def(
          "encode",
          [](const PyBatchFloatEncoder &bn, double f1, double f2) {
            return bn.Encode(f1, f2);
          },
          py::arg("cleartext_1"), py::arg("cleartext_2"),
          "Batch encode two cleartexts into one plaintext")
      .def(
          "decode",
          [](const PyBatchFloatEncoder &bn, const lib::phe::Plaintext &mp) {
            return py::make_tuple(bn.Decode<0>(mp), bn.Decode<1>(mp));
          },
          py::arg("plaintext"), "Decode plaintext and return two cleartexts")
      .doc() =
      "BatchFloatEncoder can encode two floating number into one plaintext";
}

}  // namespace heu::pylib
