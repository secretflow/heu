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

#include "heu/pylib/numpy_binding/py_slicer.h"

#include "fmt/ranges.h"

#include "heu/library/numpy/matrix.h"
#include "heu/pylib/common/traits.h"
#include "heu/pylib/numpy_binding/slice_tool.h"

namespace heu::pylib {

namespace {

template <typename T>
py::object CastMatrix(hnp::DenseMatrix<T> &&pm) {
  if (pm.ndim() == 0) {
    return py::cast(pm(0, 0));
  }
  return py::cast(std::move(pm));
}

template <typename T, typename ST_ROW, typename ST_COL>
void MatrixAssign(lib::numpy::DenseMatrix<T> *pm,
                  const slice_tool::PySlice<ST_ROW> &sr,
                  const slice_tool::PySlice<ST_COL> &sc,
                  const py::object &value) {
  if (py::isinstance<hnp::DenseMatrix<T>>(value)) {
    const auto &patch = py::cast<hnp::DenseMatrix<T>>(value);
    pm->template SetItem(sr.indices, sc.indices, patch,
                         patch.ndim() == 1 && sr.items == 1 && sc.items > 1);
    return;
  }

  if (py::isinstance<T>(value)) {
    pm->template SetItem(sr.indices, sc.indices, py::cast<T>(value));
    return;
  }

  YACL_THROW_ARGUMENT_ERROR(
      "Unsupported value type [{}] for __setitem__",
      static_cast<std::string>(py::str(value.get_type())));
}

}  // namespace

template <typename T>
py::object PySlicer<T>::GetItem(const hnp::DenseMatrix<T> &p_matrix,
                                const py::object &key) {
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

      return CastMatrix(
          p_matrix.GetItem(s_row.indices, s_col.indices, sq_row, sq_col));
    }

    // break if: continue to process 1-d case
  }

  // key is 1d and tensor is 1d or 2d
  // key dimension is less than tensor dimension
  bool sq_row;
  auto s_row = slice_tool::Parse(key, p_matrix.rows(), &sq_row);
  return CastMatrix(
      p_matrix.GetItem(s_row.indices, Eigen::placeholders::all, sq_row));
}

template <typename T>
void PySlicer<T>::SetItem(hnp::DenseMatrix<T> *p_matrix, const py::object &key,
                          const py::object &value) {
  if (py::isinstance<py::tuple>(key)) {
    auto idx_tuple = py::cast<py::tuple>(key);

    YACL_ENFORCE(static_cast<int64_t>(idx_tuple.size()) <= p_matrix->ndim(),
                 "too many indices for array, array is {}-dimensional, but "
                 "{} were indexed, slice key={}",
                 p_matrix->ndim(), idx_tuple.size(),
                 static_cast<std::string>(py::str(key)));

    if (idx_tuple.size() == 2) {
      // key id 2d and tensor is 2d
      auto s_row = slice_tool::Parse(idx_tuple[0], p_matrix->rows());
      auto s_col = slice_tool::Parse(idx_tuple[1], p_matrix->cols());

      MatrixAssign(p_matrix, s_row, s_col, value);
      return;
    }

    // break if: continue to process 1-d case
  }

  // key is 1d and tensor is 1d or 2d
  // key dimension is less than tensor dimension
  auto s_row = slice_tool::Parse(key, p_matrix->rows());
  MatrixAssign(p_matrix, s_row, slice_tool::All(p_matrix->cols()), value);
}

template class PySlicer<lib::phe::Plaintext>;
template class PySlicer<lib::phe::Ciphertext>;
template class PySlicer<std::string>;

}  // namespace heu::pylib
