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

#include "pybind11/pybind11.h"

#include "heu/library/numpy/evaluator.h"
#include "heu/library/numpy/matrix.h"

// These functions deal with slicing from python.

namespace heu::pylib {

template <typename T>
class PySlicer {
 public:
  static pybind11::object GetItem(const lib::numpy::DenseMatrix<T> &p_matrix,
                                  const pybind11::object &key);
  static void SetItem(lib::numpy::DenseMatrix<T> *p_matrix,
                      const pybind11::object &key,
                      const pybind11::object &value);
};

}  // namespace heu::pylib
