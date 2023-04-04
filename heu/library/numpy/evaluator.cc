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
#include "yacl/utils/parallel.h"

#include "heu/library/numpy/shape.h"

namespace heu::lib::numpy {

namespace {

constexpr int64_t kHeOpGrainSize = 256;

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

// define function detector
template <typename CLAZZ, typename SUB_TX, typename SUB_TY>
using kHasVectorizedAdd = decltype(std::declval<const CLAZZ&>().Add(
    absl::Span<const SUB_TX* const>(), absl::Span<const SUB_TY* const>()));
template <typename CLAZZ, typename SUB_TX, typename SUB_TY>
using kHasVectorizedSub = decltype(std::declval<const CLAZZ&>().Sub(
    absl::Span<const SUB_TX* const>(), absl::Span<const SUB_TY* const>()));
template <typename CLAZZ, typename SUB_TX, typename SUB_TY>
using kHasVectorizedMul = decltype(std::declval<const CLAZZ&>().Mul(
    absl::Span<const SUB_TX* const>(), absl::Span<const SUB_TY* const>()));

#define DO_CALL_OP(ns, OP, TX, TY)                                           \
  [&](const ns::Evaluator& sub_encryptor) {                                  \
    DoCall##OP<ns::Evaluator, ns::TX, ns::TY>(sub_encryptor, x, x_stride, y, \
                                              y_stride, &out);               \
  }

#define IMPLEMENT_DENSE_OP(OP, RET, TX, TY)                                  \
  template <typename CLAZZ, typename SUB_TX, typename SUB_TY>                \
  auto DoCall##OP(const CLAZZ& sub_evaluator, const DenseMatrix<phe::TX>& x, \
                  std::array<int64_t, 2> x_stride,                           \
                  const DenseMatrix<phe::TY>& y,                             \
                  std::array<int64_t, 2> y_stride, RET* out)                 \
      ->std::enable_if_t<std::experimental::is_detected_v<                   \
          kHasVectorized##OP, CLAZZ, SUB_TX, SUB_TY>> {                      \
    const auto* x_base = x.data();                                           \
    const auto* y_base = y.data();                                           \
    RET::value_type* out_base = out->data();                                 \
    int64_t rows = out->rows();                                              \
    yacl::parallel_for(0, out->size(), 1, [&](int64_t beg, int64_t end) {    \
      std::vector<const SUB_TX*> in_x;                                       \
      std::vector<const SUB_TY*> in_y;                                       \
      in_x.reserve(end - beg);                                               \
      in_y.reserve(end - beg);                                               \
      for (int64_t i = beg; i < end; ++i) {                                  \
        int64_t row = i % rows;                                              \
        int64_t col = i / rows;                                              \
        in_x.push_back(                                                      \
            &(x_base[row * x_stride[0] + col * x_stride[1]].As<SUB_TX>()));  \
        in_y.push_back(                                                      \
            &(y_base[row * y_stride[0] + col * y_stride[1]].As<SUB_TY>()));  \
      }                                                                      \
      auto res = sub_evaluator.OP(in_x, in_y);                               \
      for (int64_t i = beg; i < end; ++i) {                                  \
        out_base[i] = RET::value_type(std::move(res[i - beg]));              \
      }                                                                      \
    });                                                                      \
  }                                                                          \
                                                                             \
  template <typename CLAZZ, typename SUB_TX, typename SUB_TY>                \
  auto DoCall##OP(const CLAZZ& sub_evaluator, const DenseMatrix<phe::TX>& x, \
                  std::array<int64_t, 2> x_stride,                           \
                  const DenseMatrix<phe::TY>& y,                             \
                  std::array<int64_t, 2> y_stride, RET* out)                 \
      ->std::enable_if_t<!std::experimental::is_detected_v<                  \
          kHasVectorized##OP, CLAZZ, SUB_TX, SUB_TY>> {                      \
    const auto* x_base = x.data();                                           \
    const auto* y_base = y.data();                                           \
    RET::value_type* out_base = out->data();                                 \
    int64_t rows = out->rows();                                              \
    yacl::parallel_for(0, out->size(), 1, [&](int64_t beg, int64_t end) {    \
      for (int64_t i = beg; i < end; ++i) {                                  \
        int64_t row = i % rows;                                              \
        int64_t col = i / rows;                                              \
        out_base[i] = RET::value_type(                                       \
            sub_evaluator.OP(x_base[row * x_stride[0] + col * x_stride[1]]   \
                                 .template As<SUB_TX>(),                     \
                             y_base[row * y_stride[0] + col * y_stride[1]]   \
                                 .template As<SUB_TY>()));                   \
      }                                                                      \
    });                                                                      \
  }                                                                          \
                                                                             \
  RET Evaluator::OP(const DenseMatrix<phe::TX>& x,                           \
                    const DenseMatrix<phe::TY>& y) const {                   \
    Dimension sx(x);                                                         \
    Dimension sy(y);                                                         \
    YACL_ENFORCE(sx.IsCompatibleShape(sy),                                   \
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
    RET out(sz.rows, sz.cols, sz.ndim);                                      \
    std::visit(HE_DISPATCH(DO_CALL_OP, OP, TX, TY), evaluator_ptr_);         \
    return out;                                                              \
  }

IMPLEMENT_DENSE_OP(Add, CMatrix, Ciphertext, Ciphertext);
IMPLEMENT_DENSE_OP(Add, CMatrix, Ciphertext, Plaintext);
IMPLEMENT_DENSE_OP(Add, PMatrix, Plaintext, Plaintext);

CMatrix Evaluator::Add(const PMatrix& x, const CMatrix& y) const {
  return Add(y, x);
};

IMPLEMENT_DENSE_OP(Sub, CMatrix, Ciphertext, Ciphertext);
IMPLEMENT_DENSE_OP(Sub, CMatrix, Ciphertext, Plaintext);
IMPLEMENT_DENSE_OP(Sub, CMatrix, Plaintext, Ciphertext);
IMPLEMENT_DENSE_OP(Sub, PMatrix, Plaintext, Plaintext);

IMPLEMENT_DENSE_OP(Mul, CMatrix, Ciphertext, Plaintext);
IMPLEMENT_DENSE_OP(Mul, PMatrix, Plaintext, Plaintext);

CMatrix Evaluator::Mul(const PMatrix& x, const CMatrix& y) const {
  return Mul(y, x);
};

/*********   MatMul  ***********/

template <typename SUB_T1, typename SUB_T2, typename CLAZZ, typename M1,
          typename M2, typename RET>
auto DoCallMatMul(const CLAZZ& sub_evaluator, const M1& mx, const M2& my,
                  bool transpose, RET* out)
    -> std::enable_if_t<std::experimental::is_detected_v<
        kHasVectorizedMul, CLAZZ, SUB_T1, SUB_T2>> {
  // convert type for mx
  auto mx_buf = mx.data();
  auto mx_rows = mx.rows();
  std::vector<std::vector<const SUB_T1*>> in_x;
  in_x.resize(mx_rows);
  for (int64_t i = 0; i < mx_rows; ++i) {
    in_x[i].resize(mx.cols());
    for (int64_t j = 0; j < mx.cols(); ++j) {
      // There is a weird problem: mx(i, j) doesn't return a reference, it
      // returns a copy. maybe an eigen bug?
      // So we direct access underlying buffer.
      in_x[i][j] = &(mx_buf[j * mx_rows + i].template As<SUB_T1>());
    }
  }

  // convert type for my
  std::vector<std::vector<const SUB_T2*>> in_y;
  in_y.resize(my.cols());
  auto my_buf = my.data();
  int pos = 0;
  for (int64_t i = 0; i < my.cols(); ++i) {
    in_y[i].resize(my.rows());
    for (int64_t j = 0; j < my.rows(); ++j) {
      in_y[i][j] = &(my_buf[pos++].template As<SUB_T2>());
    }
  }

  out->ForEach(
      [&](int64_t row, int64_t col, typename RET::value_type* element) {
        if (transpose) {
          std::swap(row, col);
        }

        auto res = sub_evaluator.Mul(in_x[row], in_y[col]);
        auto sum = &res[0];

        for (size_t j = 1; j < res.size(); ++j) {
          // todo: use binary reduce
          sub_evaluator.AddInplace({sum}, {&res[j]});
        }
        *element = std::move(*sum);
      });
}

template <typename SUB_T1, typename SUB_T2, typename CLAZZ, typename M1,
          typename M2, typename RET>
auto DoCallMatMul(const CLAZZ& sub_evaluator, const M1& mx, const M2& my,
                  bool transpose, RET* out)
    -> std::enable_if_t<!std::experimental::is_detected_v<
        kHasVectorizedMul, CLAZZ, SUB_T1, SUB_T2>> {
  out->ForEach(
      [&](int64_t row, int64_t col, typename RET::value_type* element) {
        if (transpose) {
          std::swap(row, col);
        }

        auto sum = sub_evaluator.Mul(mx(row, 0).template As<SUB_T1>(),
                                     my(0, col).template As<SUB_T2>());
        for (int j = 1; j < mx.cols(); ++j) {
          sub_evaluator.AddInplace(
              &sum, sub_evaluator.Mul(mx(row, j).template As<SUB_T1>(),
                                      my(j, col).template As<SUB_T2>()));
        }
        *element = (std::move(sum));
      });
}

#define DO_CALL_MATMUL(ns, TX, TY)                                        \
  [&](const ns::Evaluator& sub_encryptor) {                               \
    DoCallMatMul<ns::TX, ns::TY>(sub_encryptor, mx, my, transpose, &out); \
  }

#define IMPLEMENT_DENSE_MATMUL(RET, TX, TY)                                    \
  template <typename M1, typename M2>                                          \
  RET DoMatMul##TX##TY(const M1& mx, const M2& my, int64_t out_dim,            \
                       const phe::EvaluatorType& evaluator_ptr) {              \
    int64_t ret_row = mx.rows();                                               \
    int64_t ret_col = my.cols();                                               \
    bool transpose = false;                                                    \
    if (out_dim == 1) {                                                        \
      YACL_ENFORCE(                                                            \
          ret_row == 1 || ret_col == 1,                                        \
          "internal error: matmul result is not a 1-d tensor, expected {}x{}", \
          ret_row, ret_col);                                                   \
      if (ret_col > 1) {                                                       \
        /* dim-1 matrix always a vertical vector, keep col==1 */               \
        std::swap(ret_row, ret_col);                                           \
        transpose = true;                                                      \
      }                                                                        \
    }                                                                          \
                                                                               \
    RET out(ret_row, ret_col, out_dim);                                        \
    std::visit(HE_DISPATCH(DO_CALL_MATMUL, TX, TY), evaluator_ptr);            \
    return out;                                                                \
  }                                                                            \
                                                                               \
  RET Evaluator::MatMul(const DenseMatrix<phe::TX>& x,                         \
                        const DenseMatrix<phe::TY>& y) const {                 \
    YACL_ENFORCE(                                                              \
        x.ndim() > 0 && y.ndim() > 0,                                          \
        "Input operands do not have enough dimensions, x-dim={}, y-dim{}",     \
        x.ndim(), y.ndim());                                                   \
    auto x_shape = x.shape();                                                  \
    auto y_shape = y.shape();                                                  \
    YACL_ENFORCE(x_shape[-1] == y_shape[0],                                    \
                 "dimension mismatch for matmul, x-shape={}, y-shape={}",      \
                 x_shape, y_shape);                                            \
                                                                               \
    YACL_ENFORCE(x.size() > 0 || y.size() > 0,                                 \
                 "HEU does not support empty tensor currently");               \
                                                                               \
    if (x.ndim() == 1) {                                                       \
      auto& mx = x.EigenMatrix().transpose();                                  \
      auto& my = y.EigenMatrix();                                              \
      return DoMatMul##TX##TY(mx, my, MatmulDim(x_shape, y_shape),             \
                              evaluator_ptr_);                                 \
    } else {                                                                   \
      auto& mx = x.EigenMatrix();                                              \
      auto& my = y.EigenMatrix();                                              \
      return DoMatMul##TX##TY(mx, my, MatmulDim(x_shape, y_shape),             \
                              evaluator_ptr_);                                 \
    }                                                                          \
  }

IMPLEMENT_DENSE_MATMUL(CMatrix, Ciphertext, Plaintext);
IMPLEMENT_DENSE_MATMUL(CMatrix, Plaintext, Ciphertext);
IMPLEMENT_DENSE_MATMUL(PMatrix, Plaintext, Plaintext);

template <typename T>
T Evaluator::Sum(const DenseMatrix<T>& x) const {
  YACL_ENFORCE(x.cols() > 0 && x.rows() > 0,
               "you cannot sum an empty tensor, shape={}x{}", x.rows(),
               x.cols());

  auto buf = x.data();
  return yacl::parallel_reduce<T>(
      0, x.size(), kHeOpGrainSize,
      [&](int64_t beg, int64_t end) {
        T sum = buf[beg];
        for (auto i = beg + 1; i < end; ++i) {
          phe::Evaluator::AddInplace(&sum, buf[i]);
        }
        return sum;
      },
      // todo: use binary reduce
      [&](const T& a, const T& b) { return phe::Evaluator::Add(a, b); });
}

template phe::Ciphertext Evaluator::Sum(const CMatrix&) const;
template phe::Plaintext Evaluator::Sum(const PMatrix&) const;

template <typename T>
DenseMatrix<T> Evaluator::FeatureWiseBucketSum(
    const DenseMatrix<T>& x, const Eigen::Ref<RowMatrixXd>& order_map,
    int bucket_num, bool cumsum) const {
  // the output is a dense matrix of size sum(bucket_sums) * x.shape[1]
  YACL_ENFORCE(x.cols() > 0 && x.rows() > 0,
               "you cannot sum an empty tensor, shape={}x{}", x.rows(),
               x.cols());
  YACL_ENFORCE_EQ(order_map.rows(), (x.rows()),
                  "order map and x should have same number of rows.");
  // assume all rows of order map has length feature num
  auto total_bucket_num = bucket_num * order_map.cols();
  auto res = DenseMatrix<T>(total_bucket_num, x.cols());
  FeatureWiseBucketSumInplace(x, order_map, bucket_num, res, cumsum);
  return res;
}

template CMatrix Evaluator::FeatureWiseBucketSum(
    const CMatrix&, const Eigen::Ref<RowMatrixXd>& order_map, int bucket_num,
    bool cumsum) const;

template PMatrix Evaluator::FeatureWiseBucketSum(
    const PMatrix&, const Eigen::Ref<RowMatrixXd>& order_map, int bucket_num,
    bool cumsum) const;

template <typename T>
void Evaluator::FeatureWiseBucketSumInplace(
    const DenseMatrix<T>& x, const Eigen::Ref<RowMatrixXd>& order_map,
    int bucket_num, DenseMatrix<T>& res, bool cumsum) const {
  // the output is a dense matrix of size sum(bucket_sums) * x.shape[1]
  YACL_ENFORCE(x.cols() > 0 && x.rows() > 0,
               "you cannot sum an empty tensor, shape={}x{}", x.rows(),
               x.cols());
  YACL_ENFORCE_EQ(order_map.rows(), x.rows(),
                  "order map and x should have same number of rows.");
  // assume all rows of order map has length feature num
  auto feature_num = static_cast<size_t>(order_map.cols());
  auto total_bucket_num = bucket_num * order_map.cols();

  YACL_ENFORCE_EQ(total_bucket_num, res.rows());
  YACL_ENFORCE_EQ(x.cols(), res.cols());
  T zero = GetZero(x);
  // could made this parallel
  for (auto col = 0; col < x.cols(); ++col) {
    // feature wise calculations, could be made parallel
    yacl::parallel_for(0, feature_num, 1, [&](int64_t beg_f, int64_t end_f) {
      for (auto feature_index = beg_f; feature_index < end_f; ++feature_index) {
        auto start_offset = bucket_num * feature_index;
        auto bucket_sums = yacl::parallel_reduce<std::vector<T>>(
            0, x.rows(), 4 * kHeOpGrainSize,
            [&](int64_t beg, int64_t end) {
              auto sums = std::vector<T>(bucket_num, zero);
              for (auto i = beg; i < end; ++i) {
                phe::Evaluator::AddInplace(&sums[order_map(i, feature_index)],
                                           x(i, col));
              }
              return sums;
            },
            // todo: use binary reduce
            [&](const std::vector<T>& a, const std::vector<T>& b) {
              auto result = std::vector<T>(bucket_num);
              for (auto j = 0; j < bucket_num; ++j) {
                result[j] = phe::Evaluator::Add(a[j], b[j]);
              }
              return result;
            });
        if (cumsum) {
          auto cache_sum = zero;
          for (auto i = 0; i < bucket_num; ++i) {
            phe::Evaluator::AddInplace(&cache_sum, bucket_sums[i]);
            res(i + start_offset, col) = cache_sum;
          }
        } else {
          for (auto i = 0; i < bucket_num; ++i) {
            res(i + start_offset, col) = bucket_sums[i];
          }
        }
      }
    });
  }
}

template void Evaluator::FeatureWiseBucketSumInplace(
    const CMatrix&, const Eigen::Ref<RowMatrixXd>& order_map, int bucket_num,
    CMatrix& res, bool cumsum) const;

template void Evaluator::FeatureWiseBucketSumInplace(
    const PMatrix&, const Eigen::Ref<RowMatrixXd>& order_map, int bucket_num,
    PMatrix& res, bool cumsum) const;
}  // namespace heu::lib::numpy
