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

#include "heu/library/numpy/evaluator.h"

#include "fmt/ranges.h"
#include "yasl/utils/parallel.h"

#include "heu/library/numpy/shape.h"

namespace heu::lib::numpy {

namespace {

constexpr int64_t kHeOpGrainSize = 32;

// todo: drop this class, just use Shape
struct Dimension {
  size_t rows;  // 'rows' is alias for shape[1]
  size_t cols;  // 'cols' is alias for shape[0]
  size_t ndim;  // 0 or 1 or 2

  Dimension(size_t _rows, size_t _cols, size_t _ndim)
      : rows(_rows), cols(_cols), ndim(_ndim) {}

  template <typename Matrix>
  explicit Dimension(const Matrix& mat)
      : Dimension(mat.rows(), mat.cols(), mat.ndim()) {}

  // True if `*this` and `b` have compatible shape.
  //
  // For each dimension, compatible means either dimension size is one or both
  // dimension sizes is equal. Used in broadcasting mechanism like Numpy.
  // For example:
  // 3x4 is compatible with 3x4, no broadcast.
  // 3x4 is compatible with 3x1, broadcast to 3x4.
  // 1x4 is compatible with 3x1, broadcast to 3x4.
  // 3x4 is not compatible with 3x5.
  [[nodiscard]] bool IsCompatibleShape(const Dimension& b) const {
    return (this->rows == 1 || b.rows == 1 || this->rows == b.rows) &&
           (this->cols == 1 || b.cols == 1 || this->cols == b.cols);
  }

  Dimension ComputeCastShape(const Dimension& b) {
    return {std::max(rows, b.rows), std::max(cols, b.cols),
            std::max(ndim, b.ndim)};
  }
};

std::array<int64_t, 2> ComputeCastStride(const std::array<int64_t, 2>& strides,
                                         const Dimension& sizes,
                                         const Dimension& new_sizes) {
  int64_t stride0 = (sizes.rows == new_sizes.rows) ? strides[0] : 0;
  int64_t stride1 = (sizes.cols == new_sizes.cols) ? strides[1] : 0;
  return {stride0, stride1};
}

int64_t MatmulDim(const Shape& x, const Shape& y) {
  int64_t newd;
  auto mind = std::min(x.Ndim(), y.Ndim());
  auto maxd = std::max(x.Ndim(), y.Ndim());
  if (mind == 0) {
    // matrix/vector @ scalar or scalar @ matrix/vector
    // new dim keeps same with matrix/vector
    newd = maxd;
  } else if (mind == 2) {
    // matrix @ matrix
    newd = 2;
  } else {  // mind == 1
    // matrix @ vector or vector @ matrix is 1d
    // vector @ vector is 0d
    newd = maxd - 1;
  }
  return newd;
}

}  // namespace

#define IMPLEMENT_DENSE_OP(OP, RET, TX, TY)                                  \
  RET Evaluator::OP(const DenseMatrix<TX>& x, const DenseMatrix<TY>& y)      \
      const {                                                                \
    Dimension sx(x);                                                         \
    Dimension sy(y);                                                         \
    YASL_ENFORCE(sx.IsCompatibleShape(sy),                                   \
                 "{} not supported for dim(x)={}, dim(y)={}", __func__,      \
                 (x).shape(), (y).shape());                                  \
                                                                             \
    auto sz = sx.ComputeCastShape(sy);                                       \
                                                                             \
    std::array<int64_t, 2> x_old_stride = {1, x.rows()};                     \
    std::array<int64_t, 2> y_old_stride = {1, y.rows()};                     \
    const auto x_stride = ComputeCastStride(x_old_stride, sx, sz);           \
    const auto y_stride = ComputeCastStride(y_old_stride, sy, sz);           \
                                                                             \
    const TX* x_base = x.data();                                             \
    const TY* y_base = y.data();                                             \
                                                                             \
    RET z(sz.rows, sz.cols, sz.ndim);                                        \
    z.ForEach([&](int64_t row, int64_t col,                                  \
                  typename RET::value_type* element) {                       \
      *element =                                                             \
          phe::Evaluator::OP(x_base[row * x_stride[0] + col * x_stride[1]],  \
                             y_base[row * y_stride[0] + col * y_stride[1]]); \
    });                                                                      \
    return z;                                                                \
  }

IMPLEMENT_DENSE_OP(Add, CMatrix, phe::Ciphertext, phe::Ciphertext);
IMPLEMENT_DENSE_OP(Add, CMatrix, phe::Ciphertext, phe::Plaintext);
IMPLEMENT_DENSE_OP(Add, CMatrix, phe::Plaintext, phe::Ciphertext);
IMPLEMENT_DENSE_OP(Add, PMatrix, phe::Plaintext, phe::Plaintext);

IMPLEMENT_DENSE_OP(Sub, CMatrix, phe::Ciphertext, phe::Ciphertext);
IMPLEMENT_DENSE_OP(Sub, CMatrix, phe::Ciphertext, phe::Plaintext);
IMPLEMENT_DENSE_OP(Sub, CMatrix, phe::Plaintext, phe::Ciphertext);
IMPLEMENT_DENSE_OP(Sub, PMatrix, phe::Plaintext, phe::Plaintext);

IMPLEMENT_DENSE_OP(Mul, CMatrix, phe::Ciphertext, phe::Plaintext);
IMPLEMENT_DENSE_OP(Mul, CMatrix, phe::Plaintext, phe::Ciphertext);
IMPLEMENT_DENSE_OP(Mul, PMatrix, phe::Plaintext, phe::Plaintext);

template <typename RET, typename M1, typename M2>
RET Evaluator::DoMatMul(const M1& mx, const M2& my, int64_t out_dim) const {
  int64_t ret_row = mx.rows();
  int64_t ret_col = my.cols();
  bool transpose = false;
  if (out_dim == 1) {
    YASL_ENFORCE(
        ret_row == 1 || ret_col == 1,
        "internal error: matmul result is not a 1-d tensor, expected {}x{}",
        ret_row, ret_col);
    if (ret_col > 1) {
      std::swap(ret_row, ret_col);
      transpose = true;
    }
  }

  RET out(ret_row, ret_col, out_dim);
  out.ForEach([&](int64_t row, int64_t col, typename RET::value_type* element) {
    if (transpose) {
      std::swap(row, col);
    }

    *element = phe::Evaluator::Mul(mx(row, 0), my(0, col));
    for (int j = 1; j < mx.cols(); ++j) {
      phe::Evaluator::AddInplace(element,
                                 phe::Evaluator::Mul(mx(row, j), my(j, col)));
    }
  });

  return out;
}

template <typename TX, typename TY>
auto Evaluator::MatMul(const DenseMatrix<TX>& x, const DenseMatrix<TY>& y) const
    -> DenseMatrix<decltype(phe::Evaluator::Mul(TX(), TY()))> {
  YASL_ENFORCE(
      x.ndim() > 0 && y.ndim() > 0,
      "Input operands do not have enough dimensions, x-dim={}, y-dim{}",
      x.ndim(), y.ndim());
  auto x_shape = x.shape();
  auto y_shape = y.shape();
  YASL_ENFORCE(x_shape[-1] == y_shape[0],
               "dimension mismatch for matmul, x-shape={}, y-shape={}", x_shape,
               y_shape);

  YASL_ENFORCE(x.size() > 0 || y.size() > 0,
               "HEU does not support empty tensor currently");

  using RET = DenseMatrix<decltype(phe::Evaluator::Mul(TX(), TY()))>;
  if (x.ndim() == 1) {
    auto& mx = x.EigenMatrix().transpose();
    auto& my = y.EigenMatrix();
    return DoMatMul<RET>(mx, my, MatmulDim(x_shape, y_shape));
  } else {
    auto& mx = x.EigenMatrix();
    auto& my = y.EigenMatrix();
    return DoMatMul<RET>(mx, my, MatmulDim(x_shape, y_shape));
  }
}

template CMatrix Evaluator::MatMul(const CMatrix& x, const PMatrix& y) const;
template CMatrix Evaluator::MatMul(const PMatrix& x, const CMatrix& y) const;
template PMatrix Evaluator::MatMul(const PMatrix& x, const PMatrix& y) const;

template <typename T>
T Evaluator::Sum(const DenseMatrix<T>& x) const {
  YASL_ENFORCE(x.cols() > 0 && x.rows() > 0,
               "you cannot sum an empty tensor, shape={}x{}", x.rows(),
               x.cols());

  auto buf = x.data();
  return yasl::parallel_reduce<T>(
      0, x.size(), kHeOpGrainSize,
      [&](int64_t beg, int64_t end) {
        T sum = buf[beg];
        for (auto i = beg + 1; i < end; ++i) {
          phe::Evaluator::AddInplace(&sum, buf[i]);
        }
        return sum;
      },
      [&](const T& a, const T& b) { return phe::Evaluator::Add(a, b); });
};

template phe::Ciphertext Evaluator::Sum(const CMatrix&) const;
template phe::Plaintext Evaluator::Sum(const PMatrix&) const;

}  // namespace heu::lib::numpy
