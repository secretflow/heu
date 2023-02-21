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

#include "heu/pylib/numpy_binding/extension_functions.h"

#include "fmt/ranges.h"
#include "yacl/utils/parallel.h"

#include "heu/library/numpy/matrix.h"
#include "heu/pylib/common/traits.h"
#include "heu/pylib/numpy_binding/slice_tool.h"
namespace heu::pylib {
template <typename T>
T ExtensionFunctions<T>::SelectSum(const hnp::Evaluator evaluator,
                                   const hnp::DenseMatrix<T>& p_matrix,
                                   const py::object& key) {
  if (py::isinstance<py::tuple>(key)) {
    auto idx_tuple = py::cast<py::tuple>(key);

    YACL_ENFORCE(static_cast<int64_t>(idx_tuple.size()) <= p_matrix.ndim(),
                 "too many indices for array, array is {}-dimensional, but "
                 "{} were indexed. slice key={}",
                 p_matrix.ndim(), idx_tuple.size(),
                 static_cast<std::string>(py::str(key)));

    if (idx_tuple.size() == 2) {
      // key id 2d and tensor is 2d
      bool sq_row, sq_col;
      auto s_row = slice_tool::Parse(idx_tuple[0], p_matrix.rows(), &sq_row);
      auto s_col = slice_tool::Parse(idx_tuple[1], p_matrix.cols(), &sq_col);

      return evaluator.SelectSum(p_matrix, s_row.indices, s_col.indices);
    }

    // break if: continue to process 1-d case
  }

  // key is 1d and tensor is 1d or 2d
  // key dimension is less than tensor dimension
  bool sq_row;
  auto s_row = slice_tool::Parse(key, p_matrix.rows(), &sq_row);
  return evaluator.SelectSum(p_matrix, s_row.indices, Eigen::all);
}

template <typename T>
hnp::DenseMatrix<T> ExtensionFunctions<T>::BatchSelectSum(
    const hnp::Evaluator evaluator, const hnp::DenseMatrix<T>& p_matrix,
    std::vector<py::object> key) {
  auto res = hnp::DenseMatrix<T>(key.size());
  yacl::parallel_for(0, key.size(), 1, [&](int64_t beg, int64_t end) {
    for (int64_t x = beg; x < end; ++x) {
      res(x) = ExtensionFunctions<T>::SelectSum(evaluator, p_matrix, key[x]);
    }
  });
  return res;
}

template class ExtensionFunctions<lib::phe::Plaintext>;
template class ExtensionFunctions<lib::phe::Ciphertext>;
}  // namespace heu::pylib