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

namespace heu::pylib {

namespace slice_tool {

// record one dim's slice info
template <typename INDICES_T>
struct PySlice {
  ssize_t items;
  INDICES_T indices;

  std::string ToString() { return fmt::format("PySlice index {}", indices); }
};

int64_t ComputeInt(const py::handle& src, int64_t dim_len) {
  auto idx = static_cast<int64_t>(py::cast<py::int_>(src));
  YACL_ENFORCE(idx < dim_len, "index {} is out of bounds [0, {})", idx,
               dim_len);
  if (idx < 0) {
    idx += dim_len;
    YACL_ENFORCE(idx >= 0, "index {} is out of bounds [{}, {})", idx - dim_len,
                 -dim_len, dim_len);
  }
  return idx;
}

auto Parse(const pybind11::object& src, ssize_t dim_len,
           bool* should_squeeze = nullptr) {
  PySlice<std::vector<int64_t>> res;
  bool squeeze = false;
  if (py::isinstance<py::slice>(src)) {
    auto s = py::cast<py::slice>(src);
    ssize_t start = 0, stop = 0, step = 0;
    YACL_ENFORCE(s.compute(dim_len, &start, &stop, &step, &res.items),
                 "Failed to solve slice {}", py::str(s).operator std::string());

    // todo：use Eigen::seq
    res.indices.reserve(res.items);
    YACL_ENFORCE(step != 0, "slice step cannot be 0");
    if (step > 0) {
      for (; start < stop; start += step) {
        res.indices.push_back(start);
      }
    } else {
      for (; start > stop; start += step) {
        res.indices.push_back(start);
      }
    }
  }

  else if (py::isinstance<py::sequence>(src)) {
    auto l = py::cast<py::sequence>(src);
    res.items = l.size();
    res.indices.reserve(res.items);
    for (const auto& item : l) {
      YACL_ENFORCE(
          py::isinstance<py::int_>(item),
          "indices array element must be integers, got {} with type {}",
          std::string(py::str(item)), std::string(py::str(item.get_type())));
      res.indices.push_back(ComputeInt(item, dim_len));
    }

  } else if (py::isinstance<py::int_>(src)) {
    squeeze = true;
    res.items = 1;
    res.indices.push_back(ComputeInt(src, dim_len));

  } else {
    YACL_THROW_ARGUMENT_ERROR(
        "Unsupported indices type {}",
        static_cast<std::string>(py::str(src.get_type())));
  }

  if (should_squeeze != nullptr) {
    *should_squeeze = squeeze;
  }
  return res;
}

auto All(ssize_t dim_len) -> PySlice<decltype(Eigen::all)> {
  return {dim_len, Eigen::all};
};

}  // namespace slice_tool

namespace {

template <typename T>
py::object CastMatrix(hnp::DenseMatrix<T>&& pm) {
  if (pm.ndim() == 0) {
    return py::cast(pm(0, 0));
  }
  return py::cast(std::move(pm));
}

template <typename T, typename ST_ROW, typename ST_COL>
void MatrixAssign(lib::numpy::DenseMatrix<T>* pm,
                  const slice_tool::PySlice<ST_ROW>& sr,
                  const slice_tool::PySlice<ST_COL>& sc,
                  const py::object& value) {
  if (py::isinstance<hnp::DenseMatrix<T>>(value)) {
    const auto& patch = py::cast<hnp::DenseMatrix<T>>(value);
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
py::object PySlicer<T>::GetItem(const hnp::DenseMatrix<T>& p_matrix,
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

      return CastMatrix(
          p_matrix.GetItem(s_row.indices, s_col.indices, sq_row, sq_col));
    }

    // break if: continue to process 1-d case
  }

  // key is 1d and tensor is 1d or 2d
  // key dimension is less than tensor dimension
  bool sq_row;
  auto s_row = slice_tool::Parse(key, p_matrix.rows(), &sq_row);
  return CastMatrix(p_matrix.GetItem(s_row.indices, Eigen::all, sq_row));
}

template <typename T>
void PySlicer<T>::SetItem(hnp::DenseMatrix<T>* p_matrix, const py::object& key,
                          const py::object& value) {
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
