// Copyright 2023 Ant Group Co., Ltd.
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

#include "heu/library/numpy/numpy.h"

namespace heu::lib::numpy::test {

template <typename T>
void DoAssertMatrixEq(const DenseMatrix<T> &m1, const DenseMatrix<T> &m2) {
  ASSERT_EQ(m1.rows(), m2.rows());
  ASSERT_EQ(m1.cols(), m2.cols());
  ASSERT_EQ(m1.size(), m2.size());
  ASSERT_EQ(m1.ndim(), m2.ndim());

  for (int i = 0; i < m1.rows(); ++i) {
    for (int j = 0; j < m1.cols(); ++j) {
      ASSERT_EQ(m1(i, j), m2(i, j)) << fmt::format(
          "Matrix not equal at ({}, {}). m1 is\n{}\nm2 is\n{}", i, j, m1, m2);
    }
  }
}

#define AssertMatrixEq(m1, m2)                               \
  {                                                          \
    SCOPED_TRACE("AssertMatrixEq(" #m1 ", " #m2 " Failure"); \
    DoAssertMatrixEq((m1), (m2));                            \
  }

template <typename T = PMatrix>
T GenMatrix(phe::SchemaType schema, int rows, int cols, int64_t start = 0) {
  T pts(rows, cols);
  for (int i = 0; i < rows; ++i) {
    for (int j = 0; j < cols; ++j) {
      if constexpr (std::is_same_v<typename T::value_type, phe::Plaintext>) {
        pts(i, j) = typename T::value_type(schema, start++);
      } else {
        pts(i, j) = typename T::value_type(start++);
      }
    }
  }
  return pts;
}

template <typename T = PMatrix>
T GenVector(phe::SchemaType schema, int len, int64_t start = 0) {
  T pts(len, 1, 1);
  for (int i = 0; i < len; ++i) {
    if constexpr (std::is_same_v<typename T::value_type, phe::Plaintext>) {
      pts(i, 0) = typename T::value_type(schema, start++);
    } else {
      pts(i, 0) = typename T::value_type(start++);
    }
  }

  return pts;
}

template <typename T>
DenseMatrix<T> Apply(const DenseMatrix<T> &m1, const DenseMatrix<T> &m2,
                     const std::function<T(const T &, const T &)> &func) {
  EXPECT_EQ(m1.rows(), m2.rows());
  EXPECT_EQ(m1.cols(), m2.cols());
  EXPECT_EQ(m1.ndim(), m2.ndim());

  DenseMatrix<T> res(m1.rows(), m1.cols(), m1.ndim());
  for (int i = 0; i < m1.rows(); ++i) {
    for (int j = 0; j < m1.cols(); ++j) {
      res(i, j) = func(m1(i, j), m2(i, j));
    }
  }
  return res;
}

}  // namespace heu::lib::numpy::test
