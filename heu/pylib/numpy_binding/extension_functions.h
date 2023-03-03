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

namespace heu::pylib {

template <typename T>
class ExtensionFunctions {
 public:
  static T SelectSum(const lib::numpy::Evaluator& e,
                     const lib::numpy::DenseMatrix<T>& x,
                     const pybind11::object& key);

  static lib::numpy::DenseMatrix<T> BatchSelectSum(
      const lib::numpy::Evaluator& e, const lib::numpy::DenseMatrix<T>& x,
      const std::vector<pybind11::object>& key);
};

}  // namespace heu::pylib
