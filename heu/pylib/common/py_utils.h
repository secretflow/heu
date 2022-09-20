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

#include <utility>

#include "pybind11/pybind11.h"
#include "yasl/base/int128.h"

#include "heu/library/phe/phe.h"

namespace heu::pylib {

class PyUtils {
 public:
  // py::int_ -> int128_t
  // return value 1: the int128 value
  // return value 2: is overflow (p is larger than int128)
  static std::tuple<int128_t, bool> PyIntToCppInt128(const pybind11::int_& p);

  // int128_t -> py::int_
  static pybind11::int_ CppInt128ToPyInt(int128_t num_128);

  // py::int_ -> phe::Plaintext
  // no bit size limit
  static heu::lib::phe::Plaintext PyIntToPlaintext(const pybind11::int_& p);

  // phe::Plaintext -> py::int_
  // no bit size limit
  static pybind11::int_ PlaintextToPyInt(const heu::lib::phe::Plaintext& mp);

  template <typename T>
  static decltype(auto) PickleSupport() {
    return pybind11::pickle(
        [](const T& obj) {  // __getstate__
          auto buffer = obj.Serialize();
          return pybind11::bytes(buffer.template data<char>(), buffer.size());
        },
        [](const pybind11::bytes& buffer) {  // __setstate__
          T obj;
          obj.Deserialize(static_cast<std::string_view>(buffer));
          return obj;
        });
  }

  static lib::algorithms::Endian PyEndianToCpp(const std::string& endian);
};

}  // namespace heu::pylib
