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

#include "pybind11/numpy.h"
#include "pybind11/pybind11.h"

#include "heu/library/numpy/matrix.h"
#include "heu/library/phe/phe.h"
#include "heu/pylib/common/traits.h"
#include "heu/pylib/phe_binding//py_encoders.h"

namespace heu::pylib {

// scalar encoding
template <
    typename EL_TYPE, typename Encoder_t,
    typename std::enable_if_t<std::is_same_v<Encoder_t, PyIntegerEncoder> ||
                                  std::is_same_v<Encoder_t, PyFloatEncoder> ||
                                  std::is_same_v<Encoder_t, PyBigintEncoder>,
                              int> = 0>
hnp::DenseMatrix<phe::Plaintext> DoEncodeMatrix(const py::array &ndarray,
                                                const Encoder_t &encoder) {
  YACL_ENFORCE(ndarray.ndim() <= 2,
               "HEU currently supports up to 2-dimensional tensor");
  auto bi = ndarray.request();

  // for 1-dim array: always convert to column vector
  auto rows = bi.ndim > 0 ? bi.shape[0] : 1;
  auto cols = bi.ndim > 1 ? bi.shape[1] : 1;
  hnp::DenseMatrix<phe::Plaintext> res(rows, cols, bi.ndim);

  if (ndarray.ndim() == 0) {
    res(0, 0) = encoder.Encode(*reinterpret_cast<EL_TYPE *>(bi.ptr));
    return res;
  }

  auto r = ndarray.unchecked<EL_TYPE, -1>();
  res.ForEach([&](int64_t row, int64_t col,
                  phe::Plaintext *pt) { *pt = encoder.Encode(r(row, col)); },
              !std::is_same_v<Encoder_t, PyBigintEncoder> ||
                  !std::is_same_v<EL_TYPE, PyObject *>);
  return res;
}

// batch encoding
// in/out shape: n*m*...*2 ==> n*m*...*1
// example:
// [[g1, h1],      [[p1],
//  [g2, h2],  ==>  [p2],
//  [g3, h3]]       [p3]]
template <typename EL_TYPE, typename Encoder_t,
          typename std::enable_if_t<
              std::is_same_v<Encoder_t, PyBatchIntegerEncoder> ||
                  std::is_same_v<Encoder_t, PyBatchFloatEncoder>,
              int> = 0>
hnp::DenseMatrix<phe::Plaintext> DoEncodeMatrix(const py::array &ndarray,
                                                const Encoder_t &encoder) {
  YACL_ENFORCE(ndarray.ndim() > 0 && ndarray.ndim() <= 2,
               "HEU only supports 1-dim or 2-dim array currently");

  YACL_ENFORCE(
      // TODO: support dynamic shape
      ndarray.shape(ndarray.ndim() - 1) == 2,
      "The size of innermost dimension must be 2 when using "
      "BatchIntegerEncoder/BatchFloatEncoder");

  // support shape of (2,) and (n, 2)
  auto rows = ndarray.ndim() == 1 ? 1 : ndarray.shape(0);
  auto cols = 1;
  hnp::DenseMatrix<phe::Plaintext> res(rows, cols, ndarray.ndim());
  auto r = ndarray.unchecked<EL_TYPE, -1>();

  if (ndarray.ndim() == 1) {
    // input size must be 1x2
    res(0, 0) = encoder.Encode(r(0), r(1));
    return res;
  }

  res.ForEach([&](int64_t row, int64_t, phe::Plaintext *pt) {
    *pt = encoder.Encode(r(row, 0), r(row, 1));
  });
  return res;
}

// numpy dtypes:
// dtype 0  is bool        char: ? kind: b
// dtype 1  is int8        char: b kind: i
// dtype 2  is uint8       char: B kind: u
// dtype 3  is int16       char: h kind: i
// dtype 4  is uint16      char: H kind: u
// dtype 5  is int32       char: i kind: i
// dtype 6  is uint32      char: I kind: u
// dtype 7  is int64       char: l kind: i
// dtype 8  is uint64      char: L kind: u
// dtype 9  is int64       char: q kind: i
// dtype 10 is uint64      char: Q kind: u
// dtype 11 is float32     char: f kind: f
// dtype 12 is float64     char: d kind: f
// dtype 13 is float128    char: g kind: f
// dtype 14 is complex64   char: F kind: c
// dtype 15 is complex128  char: D kind: c
// dtype 16 is complex256  char: G kind: c
// dtype 17 is object      char: O kind: O
// dtype 18 is |S0         char: S kind: S
// dtype 19 is <U0         char: U kind: U
// dtype 20 is |V0         char: V kind: V
// dtype 21 is datetime64  char: M kind: M
// dtype 22 is timedelta64 char: m kind: m
// dtype 23 is float16     char: e kind: f
template <typename Encoder_t>
hnp::DenseMatrix<phe::Plaintext> EncodeNdarray(const py::array &ndarray,
                                               const Encoder_t &encoder) {
  switch (ndarray.dtype().num()) {
    case 1:
      return DoEncodeMatrix<int8_t>(ndarray, encoder);
    case 2:
      return DoEncodeMatrix<uint8_t>(ndarray, encoder);
    case 3:
      return DoEncodeMatrix<int16_t>(ndarray, encoder);
    case 4:
      return DoEncodeMatrix<uint16_t>(ndarray, encoder);
    case 5:
      return DoEncodeMatrix<int32_t>(ndarray, encoder);
    case 6:
      return DoEncodeMatrix<uint32_t>(ndarray, encoder);
    case 7:
      return DoEncodeMatrix<int64_t>(ndarray, encoder);
    case 8:
      return DoEncodeMatrix<uint64_t>(ndarray, encoder);
    case 9:
      return DoEncodeMatrix<int64_t>(ndarray, encoder);
    case 10:
      return DoEncodeMatrix<uint64_t>(ndarray, encoder);
    case 11:
      return DoEncodeMatrix<float>(ndarray, encoder);
    case 12:
      return DoEncodeMatrix<double>(ndarray, encoder);
    case 17:
      return DoEncodeMatrix<PyObject *>(ndarray, encoder);
    default:
      YACL_THROW_ARGUMENT_ERROR("Unsupported numpy ndarray with dtype '{}'",
                                std::string(py::str(ndarray.dtype())));
  }
}

py::array ParseNumpyNdarray(PyObject *ptr, int extra_flags) {
  YACL_ENFORCE(ptr != nullptr,
               "HEU cannot create a numpy.ndarray from nullptr");

  return py::reinterpret_steal<py::array>(
      py::detail::npy_api::get().PyArray_FromAny_(
          ptr, nullptr, 0, 0,
          py::detail::npy_api::NPY_ARRAY_ENSUREARRAY_ | extra_flags, nullptr));
}

template <typename Encoder_t>
hnp::DenseMatrix<phe::Plaintext> ParseEncodeNdarray(const py::object &ptr,
                                                    const Encoder_t &encoder) {
  return EncodeNdarray(ParseNumpyNdarray(ptr.ptr(), py::array::forcecast),
                       encoder);
}

}  // namespace heu::pylib
