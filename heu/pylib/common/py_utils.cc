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

#include "heu/pylib/common/py_utils.h"

#include "heu/library/phe/phe.h"

namespace heu::pylib {

namespace py = ::pybind11;
namespace phe = ::heu::lib::phe;

// const PyObject values
const static auto kPyObjValue64 =
    py::reinterpret_steal<py::object>(PyLong_FromLong(64));
const static auto kPyObjUint64Mask = py::reinterpret_steal<py::object>(
    PyLong_FromUnsignedLongLong(~uint64_t{0}));

// NOT thread safe
std::tuple<int128_t, bool> PyUtils::PyIntToCppInt128(const py::int_ &p) {
  // ref python c api: https://docs.python.org/3/c-api/long.html
  int is_overflow;
  int64_t n64 = PyLong_AsLongLongAndOverflow(p.ptr(), &is_overflow);
  if (is_overflow == 0) {
    return {n64, false};
  }

  auto lo_obj = py::reinterpret_steal<py::object>(
      PyNumber_And(p.ptr(), kPyObjUint64Mask.ptr()));
  auto lo = PyLong_AsUnsignedLongLong(lo_obj.ptr());

  auto hi_obj = py::reinterpret_steal<py::object>(
      PyNumber_Rshift(p.ptr(), kPyObjValue64.ptr()));
  auto hi = PyLong_AsLongLongAndOverflow(hi_obj.ptr(), &is_overflow);

  return {yacl::MakeInt128(hi, lo), is_overflow};
}

// NOT thread safe
py::int_ PyUtils::CppInt128ToPyInt(int128_t num_128) {
  auto hi_obj = py::reinterpret_steal<py::object>(
      PyLong_FromLongLong(static_cast<int64_t>(
          static_cast<uint64_t>(static_cast<uint128_t>(num_128) >> 64))));
  auto hi = py::reinterpret_steal<py::object>(
      PyNumber_Lshift(hi_obj.ptr(), kPyObjValue64.ptr()));
  auto lo = py::reinterpret_steal<py::object>(PyLong_FromUnsignedLongLong(
      static_cast<uint64_t>(num_128 & ~uint64_t{0})));

  return py::reinterpret_steal<py::int_>(PyNumber_Add(hi.ptr(), lo.ptr()));
}

// NOT thread safe
phe::Plaintext PyUtils::PyIntToPlaintext(phe::SchemaType schema,
                                         const py::int_ &p) {
  auto [v, overflow] = PyIntToCppInt128(p);
  if (overflow) {
    phe::Plaintext pt(schema);
    pt.SetValue(py::str(static_cast<py::object>(p)), 10);
    return pt;
  } else {
    return phe::Plaintext(schema, v);
  }
}

// NOT thread safe
py::int_ PyUtils::PlaintextToPyInt(const phe::Plaintext &mp) {
  if (mp.BitCount() < 64) {  // Up to 63bit regardless of sign bit
    return {mp.GetValue<int64_t>()};
  }

  if (mp.BitCount() < 127) {
    return CppInt128ToPyInt(mp.GetValue<int128_t>());
  }

  return py::reinterpret_steal<py::int_>(
      PyLong_FromString(mp.ToHexString().c_str(), nullptr, 16));
}

lib::algorithms::Endian PyUtils::PyEndianToCpp(const std::string &endian) {
  if (endian == "little") {
    return lib::algorithms::Endian::little;
  } else if (endian == "big") {
    return lib::algorithms::Endian::big;
  } else {
    YACL_THROW_ARGUMENT_ERROR("Illegal endian {}", endian);
  }
}

}  // namespace heu::pylib
