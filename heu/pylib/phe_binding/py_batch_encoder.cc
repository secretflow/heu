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

yasl::Buffer PyBatchEncoder::Serialize() const { return encoder_.Serialize(); }

PyBatchEncoder PyBatchEncoder::LoadFrom(yasl::ByteContainerView buf) {
  return PyBatchEncoder(lib::phe::BatchEncoder::LoadFrom(buf));
}

std::string PyBatchEncoder::ToString() const { return encoder_.ToString(); }

std::string PyBatchEncoderParams::ToString() const {
  return fmt::format("BatchEncoderParams(padding_size={})", padding_size);
}

void BindPyBatchEncoder(pybind11::module &m) {
  namespace py = ::pybind11;

  py::class_<PyBatchEncoderParams>(m, "BatchEncoderParams")
      .def(py::init<size_t>(), py::arg("padding_size") = 32,
           "parameters for BigintEncoder")
      .def("__str__", &PyBatchEncoderParams::ToString)
      .def("__repr__", &PyBatchEncoderParams::ToString)
      .def("instance", &PyBatchEncoderParams::Instance,
           "Create BatchEncoder instance");

  py::class_<PyBatchEncoder>(m, "BatchEncoder")
      .def(py::init<lib::phe::SchemaType, size_t>(), py::arg("schema"),
           py::arg("padding_size") = 32)
      .def("__str__", &PyBatchEncoder::ToString)
      .def("__repr__",
           [](const PyBatchEncoder &bn) {
             return fmt::format("BatchEncoder(schema={}, padding_size={})",
                                bn.GetSchema(), bn.GetPaddingSize());
           })
      .def(PyUtils::PickleSupport<PyBatchEncoder>())
      .def("encode", &PyBatchEncoder::Encode<int64_t>, py::arg("cleartext_1"),
           py::arg("cleartext_2"),
           "Batch encode two cleartexts into one plaintext")
      .def(
          "decode",
          [](const PyBatchEncoder &bn, const lib::phe::Plaintext &mp) {
            return py::make_tuple(bn.Decode<0>(mp), bn.Decode<1>(mp));
          },
          py::arg("plaintext"), "Decode plaintext and return two cleartexts")
      .doc() =
      "Encode two cleartexts into one plaintext.\n\n"
      "Cleartexts must be integers and cannot exceed 64bit.";
}

}  // namespace heu::pylib
