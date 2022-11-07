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
#include "yasl/utils/parallel.h"

#include "heu/library/numpy/matrix.h"
#include "heu/library/phe/phe.h"
#include "heu/pylib/common/traits.h"
#include "heu/pylib/phe_binding/py_encoders.h"

namespace heu::pylib {

// Decode PMatrix to python numpy.ndarray
// Note: PyIntegerEncoder and PyFloatEncoder support parallel decoding,
// PyBigintEncoder needs to call back python interpreter interface, so
// parallel decoding is not supported.
// (Because python interpreter is not thread safe)
template <typename Encoder_t>
py::array DecodeNdarray(
    const lib::numpy::PMatrix &in,
    const std::enable_if_t<std::is_same_v<Encoder_t, PyIntegerEncoder> ||
                               std::is_same_v<Encoder_t, PyFloatEncoder> ||
                               std::is_same_v<Encoder_t, PyBigintDecoder>,
                           Encoder_t> &encoder) {
  auto rows = in.rows();
  auto cols = in.cols();

  // this buffer will free in python side (numpy)
  // https://stackoverflow.com/questions/49179356/pybind11-create-and-return-numpy-array-from-c-side
  if (in.ndim() == 0) {
    YASL_ENFORCE(rows == 1 && cols == 1,
                 "internal error: 0-dimensional tensor has shape {}x{}", rows,
                 cols);

    return py::array(encoder.DecodeAsPyObj(in(0, 0)));
  }

  py::array res;
  if (in.ndim() == 1) {
    YASL_ENFORCE(cols == 1, "vertical vector's cols() must be 1");
    res = py::array(py::dtype(Encoder_t::DefaultPyTypeFormat),
                    py::array::ShapeContainer({rows}));
  } else {
    res = py::array(py::dtype(Encoder_t::DefaultPyTypeFormat), {rows, cols});
  }

  auto r = res.template mutable_unchecked<typename Encoder_t::DefaultPlainT>();

  std::function<void(int64_t, int64_t)> pfunc;
  if (in.ndim() == 1) {
    pfunc = [&](int64_t beg, int64_t end) {
      for (int64_t row = beg; row < end; ++row) {
        r(row) = encoder.template Decode<typename Encoder_t::DefaultPlainT>(
            in(row, 0));
      }
    };
  } else {
    pfunc = [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        int64_t row = i / cols;
        int64_t col = i % cols;
        r(row, col) =
            encoder.template Decode<typename Encoder_t::DefaultPlainT>(
                in(row, col));
      }
    };
  }

  if constexpr (std::is_base_of_v<Encoder_t, PyBigintDecoder>) {
    pfunc(0, in.size());
  } else {
    yasl::parallel_for(0, in.size(), kHeOpGrainSize, pfunc);
  }
  return res;
}

// batch decode
// [[p1],  ==> [[g1, h1],
//  [p2],  ==>  [g2, h2],
//  [p3]]  ==>  [g3, h3]]
template <typename Encoder_t>
py::array DecodeNdarray(
    const lib::numpy::PMatrix &in,
    const std::enable_if_t<std::is_same_v<Encoder_t, PyBatchEncoder>, Encoder_t>
        &encoder) {
  YASL_ENFORCE(
      in.cols() == 1,
      "The size of innermost dimension must be 1 when using PyBatchEncoder");

  int rows = in.rows();
  py::array res;
  if (in.ndim() <= 1) {
    // in matrix is 1x1
    YASL_ENFORCE(in.rows() == 1, "0d/1d-array's size must be 1x2 currently");
    res = py::array(py::dtype(Encoder_t::DefaultPyTypeFormat),
                    py::array::ShapeContainer({2}));
  } else {
    res = py::array(py::dtype(Encoder_t::DefaultPyTypeFormat), {rows, 2});
  }

  auto r = res.template mutable_unchecked<typename Encoder_t::DefaultPlainT>();
  if (in.ndim() == 1) {
    r(0) = encoder.template Decode<0>(in(0, 0));
    r(1) = encoder.template Decode<1>(in(0, 0));
    return res;
  }

  yasl::parallel_for(0, in.size(), kHeOpGrainSize,
                     [&](int64_t beg, int64_t end) {
                       for (int64_t row = beg; row < end; ++row) {
                         const auto &pt = in(row, 0);
                         r(row, 0) = encoder.template Decode<0>(pt);
                         r(row, 1) = encoder.template Decode<1>(pt);
                       }
                     });
  return res;
}

}  // namespace heu::pylib
