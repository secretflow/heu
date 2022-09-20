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

#include "heu/library/numpy/numpy.h"

#include "gtest/gtest.h"

namespace heu::lib::numpy::test {

namespace {

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
T GenMatrix(int rows, int cols, int64_t start = 0) {
  T pts(rows, cols);
  for (int i = 0; i < rows; ++i) {
    for (int j = 0; j < cols; ++j) {
      pts(i, j) = typename T::value_type(start++);
    }
  }
  return pts;
}

template <typename T = PMatrix>
T GenVector(int len, int64_t start = 0) {
  T pts(len, 1, 1);
  for (int i = 0; i < len; ++i) {
    pts(i, 0) = typename T::value_type(start++);
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

}  // namespace

class NumpyTest : public ::testing::Test {
 protected:
  HeKit he_kit_ = HeKit(phe::HeKit(phe::SchemaType::ZPaillier, 2048));
};

TEST_F(NumpyTest, PtSerializeWorks) {
  auto pts1 = GenVector(100);

  // buffer serialize
  auto buf = pts1.Serialize();
  ASSERT_GT(buf.size(), 0);
  DenseMatrix<phe::Plaintext> pts2;
  pts2.Deserialize(buf);
  AssertMatrixEq(pts1, pts2);

  // msgpack serialize
  std::stringstream ss;
  msgpack::pack(ss, pts2);

  msgpack::object_handle oh;
  msgpack::unpack(oh, ss.str().data(), ss.str().size());
  auto pts3 = oh.get().as<decltype(pts2)>();
  AssertMatrixEq(pts1, pts3);
  AssertMatrixEq(pts2, pts3);
}

TEST_F(NumpyTest, CtSerializeWorks) {
  auto cts1 = he_kit_.GetEncryptor()->Encrypt(GenMatrix(10, 30));

  std::stringstream ss;
  msgpack::pack(ss, cts1);

  msgpack::object_handle oh;
  msgpack::unpack(oh, ss.str().data(), ss.str().size());
  auto cts2 = oh.get().as<decltype(cts1)>();
  AssertMatrixEq(cts1, cts2);
}

TEST_F(NumpyTest, EvalWorks) {
  auto pts1 = GenMatrix(30, 10);
  auto pts2 = GenMatrix(30, 10);
  auto cts1 = he_kit_.GetEncryptor()->Encrypt(pts1);
  auto cts2 = he_kit_.GetEncryptor()->Encrypt(pts2);

  // add
  std::function<phe::Plaintext(const phe::Plaintext &, const phe::Plaintext &)>
      op = std::plus<phe::Plaintext>();
  auto pts_sum = he_kit_.GetEvaluator()->Add(pts1, pts2);
  AssertMatrixEq(pts_sum, Apply(pts1, pts2, op));

  auto cts3 = he_kit_.GetEvaluator()->Add(cts1, cts2);
  AssertMatrixEq(he_kit_.GetDecryptor()->Decrypt(cts3), pts_sum);

  cts3 = he_kit_.GetEvaluator()->Add(cts1, pts2);
  AssertMatrixEq(he_kit_.GetDecryptor()->Decrypt(cts3), pts_sum);

  cts3 = he_kit_.GetEvaluator()->Add(pts1, cts2);
  AssertMatrixEq(he_kit_.GetDecryptor()->Decrypt(cts3), pts_sum);

  // sub
  op = std::minus<phe::Plaintext>();
  auto pts_minus = he_kit_.GetEvaluator()->Sub(pts1, pts2);
  AssertMatrixEq(pts_minus, Apply(pts1, pts2, op));

  cts3 = he_kit_.GetEvaluator()->Sub(cts1, cts2);
  AssertMatrixEq(he_kit_.GetDecryptor()->Decrypt(cts3), pts_minus);

  cts3 = he_kit_.GetEvaluator()->Sub(cts1, pts2);
  AssertMatrixEq(he_kit_.GetDecryptor()->Decrypt(cts3), pts_minus);

  cts3 = he_kit_.GetEvaluator()->Sub(pts1, cts2);
  AssertMatrixEq(he_kit_.GetDecryptor()->Decrypt(cts3), pts_minus);

  // mul
  op = std::multiplies<phe::Plaintext>();
  auto pts_multiplies = he_kit_.GetEvaluator()->Mul(pts1, pts2);
  AssertMatrixEq(pts_multiplies, Apply(pts1, pts2, op));

  cts3 = he_kit_.GetEvaluator()->Mul(cts1, pts2);
  AssertMatrixEq(he_kit_.GetDecryptor()->Decrypt(cts3), pts_multiplies);

  cts3 = he_kit_.GetEvaluator()->Mul(pts1, cts2);
  AssertMatrixEq(he_kit_.GetDecryptor()->Decrypt(cts3), pts_multiplies);

  cts3 = he_kit_.GetEvaluator()->Mul(GenMatrix<DenseMatrix<int128_t>>(30, 10),
                                     cts2);
  AssertMatrixEq(he_kit_.GetDecryptor()->Decrypt(cts3), pts_multiplies);

  cts3 = he_kit_.GetEvaluator()->Mul(cts1,
                                     GenMatrix<DenseMatrix<int128_t>>(30, 10));
  AssertMatrixEq(he_kit_.GetDecryptor()->Decrypt(cts3), pts_multiplies);
}

TEST_F(NumpyTest, EvalDimWorks) {
  auto pts_sum = he_kit_.GetEvaluator()->Add(GenMatrix(2, 2), GenMatrix(2, 2));
  EXPECT_EQ(pts_sum.ndim(), 2);

  pts_sum = he_kit_.GetEvaluator()->Add(GenMatrix(1, 1), GenMatrix(1, 1));
  EXPECT_EQ(pts_sum.ndim(), 2);

  pts_sum = he_kit_.GetEvaluator()->Add(GenVector(10), GenVector(10));
  EXPECT_EQ(pts_sum.ndim(), 1);
}

TEST_F(NumpyTest, SumWorks) {
  auto m = GenMatrix(30, 30);
  auto sum = he_kit_.GetEvaluator()->Sum(m);
  EXPECT_EQ(sum, algorithms::Plaintext(899 * 900 / 2));

  auto m2 = he_kit_.GetEncryptor()->Encrypt(m);
  auto sum2 = he_kit_.GetEvaluator()->Sum(m2);
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(sum2),
            algorithms::Plaintext(899 * 900 / 2));
}

class MatmulTest : public ::testing::TestWithParam<std::tuple<int, int, int>> {
 protected:
  HeKit he_kit_ = HeKit(phe::HeKit(phe::SchemaType::ZPaillier, 2048));
};

// matrix's N,K,M
INSTANTIATE_TEST_SUITE_P(
    NormalCase, MatmulTest,
    testing::Values(std::make_tuple(1, 1, 1), std::make_tuple(1, 1, 20),
                    std::make_tuple(10, 1, 1), std::make_tuple(1, 100, 1),
                    std::make_tuple(10, 1, 20), std::make_tuple(20, 30, 1),
                    std::make_tuple(1, 100, 3), std::make_tuple(2, 3, 4),
                    std::make_tuple(10, 30, 20)));

TEST_P(MatmulTest, MatmulWorks) {
  int n = std::get<0>(GetParam());
  int k = std::get<1>(GetParam());
  int m = std::get<2>(GetParam());
  auto in1 = GenMatrix<Eigen::Matrix<int64_t, Eigen::Dynamic, Eigen::Dynamic>>(
      n, k, 10);
  auto pts1 = GenMatrix(n, k, 10);

  auto in2 = GenMatrix<Eigen::Matrix<int64_t, Eigen::Dynamic, Eigen::Dynamic>>(
      k, m, 5);
  auto pts2 = GenMatrix(k, m, 5);

  Eigen::Matrix<int64_t, Eigen::Dynamic, Eigen::Dynamic> ans_tmp = in1 * in2;
  PMatrix ans(ans_tmp.rows(), ans_tmp.cols());
  for (int i = 0; i < ans_tmp.rows(); ++i) {
    for (int j = 0; j < ans_tmp.cols(); ++j) {
      ans(i, j) = phe::Plaintext(ans_tmp(i, j));
    }
  }

  // pt * pt
  auto pts3 = he_kit_.GetEvaluator()->MatMul(pts1, pts2);
  AssertMatrixEq(ans, pts3);

  // ct * pt
  auto cts1 = he_kit_.GetEncryptor()->Encrypt(pts1);
  auto cts3 = he_kit_.GetEvaluator()->MatMul(cts1, pts2);
  AssertMatrixEq(ans, he_kit_.GetDecryptor()->Decrypt(cts3));

  // pt * ct
  auto cts2 = he_kit_.GetEncryptor()->Encrypt(pts2);
  cts3 = he_kit_.GetEvaluator()->MatMul(pts1, cts2);
  AssertMatrixEq(ans, he_kit_.GetDecryptor()->Decrypt(cts3));

  auto its1 = GenMatrix<DenseMatrix<int128_t>>(n, k, 10);
  auto its2 = GenMatrix<DenseMatrix<int128_t>>(k, m, 5);
  // ct * int128
  cts3 = he_kit_.GetEvaluator()->MatMul(cts1, its2);
  AssertMatrixEq(ans, he_kit_.GetDecryptor()->Decrypt(cts3));
  // int128 * ct
  cts3 = he_kit_.GetEvaluator()->MatMul(its1, cts2);
  AssertMatrixEq(ans, he_kit_.GetDecryptor()->Decrypt(cts3));
}

}  // namespace heu::lib::numpy::test
