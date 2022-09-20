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

#include "heu/pylib/phe_binding/bind_encoder.h"

#include "heu/library/phe/phe.h"
#include "heu/pylib/common/py_encoders.h"

namespace heu::pylib {

namespace py = ::pybind11;
namespace phe = ::heu::lib::phe;

void PyBindEncoders(pybind11::module& m) {
  py::class_<PyIntegerEncoder>(m, "IntegerEncoder")
      .def(py::init<int64_t>(), py::arg("scale"))
      .def(py::init<>(), "Create an integer encoder using default scale")
      .def("__str__", &PyIntegerEncoder::ToString)
      .def("__repr__", &PyIntegerEncoder::ToString)
      .def(PyUtils::PickleSupport<PyIntegerEncoder>())
      .def(
          "encode",
          [](const PyIntegerEncoder& pe, const py::int_& p) {
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

  py::class_<PyFloatEncoder>(m, "FloatEncoder")
      .def(py::init<int64_t>(), py::arg("scale"))
      .def(py::init<>(), "Create a float encoder using default scale")
      .def("__str__", &PyFloatEncoder::ToString)
      .def("__repr__", &PyFloatEncoder::ToString)
      .def(PyUtils::PickleSupport<PyFloatEncoder>())
      .def("encode", &PyFloatEncoder::Encode<double>, py::arg("cleartext"),
           "Encode a float number into plaintext")
      .def(
          "encode",
          [](const PyFloatEncoder& pe, const py::int_& p) {
            return pe.Encode(p);
          },
          py::arg("cleartext"), "Encode an int128 number into plaintext")
      .def("decode", &PyFloatEncoder::Decode<double>, py::arg("plaintext"),
           "Decode plaintext to float number")
      .doc() =
      "Encode cleartext into plaintext.\n\n"
      "The cleartext can be a floating point number";

  py::class_<PyBigintEncoder>(m, "BigintEncoder")
      .def(py::init<>(), "Create a bigint encoder")
      .def("__str__", &PyBigintEncoder::ToString)
      .def("__repr__", &PyBigintEncoder::ToString)
      .def(PyUtils::PickleSupport<PyBigintEncoder>())
      .def(
          "encode",
          [](const PyBigintEncoder& pe, const py::int_& p) {
            return pe.Encode(p);
          },
          py::arg("cleartext"), "Encode python int number into plaintext")
      .def("decode", &PyBigintEncoder::DecodeAsPyObj, py::arg("plaintext"),
           "Decode plaintext to python int number")
      .doc() =
      "Encode cleartext into plaintext.\n\n"
      "PyBigintEncoder supports arbitrary precision integers";

  py::class_<PyBatchEncoder>(m, "BatchEncoder")
      .def(py::init<size_t>(), py::arg("padding_size") = 32)
      .def("__str__", &PyBatchEncoder::ToString)
      // todo: __repr__ impl
      .def(PyUtils::PickleSupport<PyBatchEncoder>())
      .def("encode", &PyBatchEncoder::Encode<int64_t>, py::arg("cleartext_1"),
           py::arg("cleartext_2"),
           "Batch encode two cleartexts into one plaintext")
      .def(
          "decode",
          [](const PyBatchEncoder& bn, const phe::Plaintext& mp) {
            return py::make_tuple(bn.Decode<0>(mp), bn.Decode<1>(mp));
          },
          py::arg("plaintext"), "Decode plaintext and return two cleartexts")
      .doc() =
      "Encode two cleartexts into one plaintext.\n\n"
      "Cleartexts must be integers and cannot exceed 64bit.";
}

}  // namespace heu::pylib
