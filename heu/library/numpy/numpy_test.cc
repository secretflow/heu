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

#include "heu/library/numpy/eigen_traits.h"

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

}  // namespace

class NumpyTest : public ::testing::Test {
 protected:
  HeKit he_kit_ = HeKit(phe::HeKit(phe::SchemaType::OU, 2048));
};

TEST_F(NumpyTest, PtSerializeWorks) {
  auto pts1 = GenVector(he_kit_.GetSchemaType(), 100);

  // buffer serialize
  auto buf = pts1.Serialize();
  ASSERT_GT(buf.size(), 0);
  DenseMatrix<phe::Plaintext> pts2 = DenseMatrix<phe::Plaintext>::LoadFrom(buf);
  AssertMatrixEq(pts1, pts2);
}

TEST_F(NumpyTest, CtSerializeWorks) {
  auto cts1 = he_kit_.GetEncryptor()->Encrypt(
      GenMatrix(he_kit_.GetSchemaType(), 10, 30));

  auto buf = cts1.Serialize();
  std::string str = std::string(buf.data<char>(), buf.size());
  auto cts2 = DenseMatrix<phe::Ciphertext>::LoadFrom(str);
  AssertMatrixEq(cts1, cts2);
}

TEST_F(NumpyTest, EvalWorks) {
  auto pts1 = GenMatrix(he_kit_.GetSchemaType(), 30, 10);
  auto pts2 = GenMatrix(he_kit_.GetSchemaType(), 30, 10);
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
}

TEST_F(NumpyTest, EvalDimWorks) {
  auto pts_sum =
      he_kit_.GetEvaluator()->Add(GenMatrix(he_kit_.GetSchemaType(), 2, 2),
                                  GenMatrix(he_kit_.GetSchemaType(), 2, 2));
  EXPECT_EQ(pts_sum.ndim(), 2);

  pts_sum =
      he_kit_.GetEvaluator()->Add(GenMatrix(he_kit_.GetSchemaType(), 1, 1),
                                  GenMatrix(he_kit_.GetSchemaType(), 1, 1));
  EXPECT_EQ(pts_sum.ndim(), 2);

  pts_sum = he_kit_.GetEvaluator()->Add(GenVector(he_kit_.GetSchemaType(), 10),
                                        GenVector(he_kit_.GetSchemaType(), 10));
  EXPECT_EQ(pts_sum.ndim(), 1);
}

TEST_F(NumpyTest, SumWorks) {
  auto m = GenMatrix(he_kit_.GetSchemaType(), 30, 30);
  auto sum = he_kit_.GetEvaluator()->Sum(m);
  EXPECT_EQ(sum.GetValue<int64_t>(), 899 * 900 / 2);

  auto m2 = he_kit_.GetEncryptor()->Encrypt(m);
  auto sum2 = he_kit_.GetEvaluator()->Sum(m2);
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(sum2).GetValue<int64_t>(),
            899 * 900 / 2);
}

TEST_F(NumpyTest, SelectSumWorks) {
  auto m = GenMatrix(he_kit_.GetSchemaType(), 30, 30);
  std::vector<int64_t> a{0}, b{0, 1};

  auto sum = he_kit_.GetEvaluator()->SelectSum(m, a, a);
  EXPECT_EQ(sum.GetValue<int64_t>(), 0);

  auto m2 = he_kit_.GetEncryptor()->Encrypt(m);
  auto sum2 = he_kit_.GetEvaluator()->SelectSum(m2, b, b);
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(sum2).GetValue<int64_t>(),
            0 + 1 + 30 + 31);
}

TEST_F(NumpyTest, BinSumWorks) {
  auto m = GenMatrix(he_kit_.GetSchemaType(), 5, 2);
  // whole group
  std::vector<size_t> subgroup_indices({2, 3, 4});

  // 1 feature all in 0th bucket
  RowMatrixXd order_map({{1, 3, 2, 2, 3, 3, 0, 0, 0, 0},
                         {2, 3, 0, 1, 0, 1, 2, 3, 0, 1},
                         {2, 1, 1, 1, 0, 2, 0, 1, 1, 1},
                         {3, 2, 2, 0, 0, 1, 1, 1, 2, 3},
                         {0, 0, 2, 2, 3, 3, 0, 3, 2, 2}});
  auto bucket_num = 5;
  auto sum = he_kit_.GetEvaluator()->FeatureWiseBucketSum(
      m.GetItem(subgroup_indices, Eigen::all),
      order_map(subgroup_indices, Eigen::all), bucket_num)(2, 0);
  EXPECT_EQ(sum.GetValue<int64_t>(), 4);
}

TEST_F(NumpyTest, RangeCheckWorks) {
  auto pmatrix = GenMatrix(he_kit_.GetSchemaType(), 25, 25);
  auto cmatrix = he_kit_.GetEncryptor()->Encrypt(pmatrix);
  EXPECT_NO_THROW(he_kit_.GetDecryptor()->DecryptInRange(cmatrix, 64));

  he_kit_.GetEvaluator()->MulInplace(
      &cmatrix(3, 3), phe::Plaintext(he_kit_.GetSchemaType(),
                                     std::numeric_limits<int64_t>::max()));
  EXPECT_ANY_THROW(he_kit_.GetDecryptor()->DecryptInRange(cmatrix, 64));
  EXPECT_NO_THROW(he_kit_.GetDecryptor()->Decrypt(cmatrix));

  // two point overflows, test throw exception in different thread
  he_kit_.GetEvaluator()->MulInplace(
      &cmatrix(23, 23), phe::Plaintext(he_kit_.GetSchemaType(),
                                       std::numeric_limits<int64_t>::max()));
  EXPECT_ANY_THROW(he_kit_.GetDecryptor()->DecryptInRange(cmatrix, 64));
  EXPECT_NO_THROW(he_kit_.GetDecryptor()->Decrypt(cmatrix));

  // check all thread throw exception
  EXPECT_ANY_THROW(he_kit_.GetDecryptor()->DecryptInRange(cmatrix, 1));
  EXPECT_NO_THROW(he_kit_.GetDecryptor()->Decrypt(cmatrix));
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
      he_kit_.GetSchemaType(), n, k, 10);
  auto pts1 = GenMatrix(he_kit_.GetSchemaType(), n, k, 10);

  auto in2 = GenMatrix<Eigen::Matrix<int64_t, Eigen::Dynamic, Eigen::Dynamic>>(
      he_kit_.GetSchemaType(), k, m, 5);
  auto pts2 = GenMatrix(he_kit_.GetSchemaType(), k, m, 5);

  Eigen::Matrix<int64_t, Eigen::Dynamic, Eigen::Dynamic> ans_tmp = in1 * in2;
  PMatrix ans(ans_tmp.rows(), ans_tmp.cols());
  for (int i = 0; i < ans_tmp.rows(); ++i) {
    for (int j = 0; j < ans_tmp.cols(); ++j) {
      ans(i, j) = phe::Plaintext(he_kit_.GetSchemaType(), ans_tmp(i, j));
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
}

}  // namespace heu::lib::numpy::test
