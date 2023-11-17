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

#include "gtest/gtest.h"

#include "heu/library/numpy/test/test_tools.h"

namespace heu::lib::numpy::test {

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
  // plaintext case
  auto m = GenMatrix(he_kit_.GetSchemaType(), 30, 30);
  std::vector<int64_t> a{0}, b{0, 1};

  EXPECT_EQ(he_kit_.GetEvaluator()
                ->SelectSum(m, std::vector<int64_t>(), std::vector<int64_t>())
                .GetValue<int64_t>(),
            0);

  auto sum = he_kit_.GetEvaluator()->SelectSum(m, a, a);
  EXPECT_EQ(sum.GetValue<int64_t>(), 0);

  // ciphertext case
  auto m2 = he_kit_.GetEncryptor()->Encrypt(m);
  auto sum2 = he_kit_.GetEvaluator()->SelectSum(m2, b, b);
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(sum2).GetValue<int64_t>(),
            0 + 1 + 30 + 31);

  // ciphertext case from scql
  PMatrix plain_in(5, 1);
  plain_in(0, 0) = 0_mp;
  plain_in(1, 0) = 0_mp;
  plain_in(2, 0) = 1000000_mp;
  plain_in(3, 0) = 1000000_mp;
  plain_in(4, 0) = 0_mp;

  CMatrix encrypted_in = he_kit_.GetEncryptor()->Encrypt(plain_in);
  auto buf = encrypted_in.Serialize();
  auto encrypted_in2 = CMatrix ::LoadFrom(buf);
  ASSERT_EQ(encrypted_in.rows(), encrypted_in2.rows());
  ASSERT_EQ(encrypted_in.cols(), encrypted_in2.cols());
  ASSERT_EQ(encrypted_in.ndim(), encrypted_in2.ndim());

  auto encrypted_sum = he_kit_.GetEvaluator()->SelectSum(
      encrypted_in2, std::vector<int64_t>{0, 1}, std::vector<int64_t>{0});
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(encrypted_sum).GetValue<int64_t>(),
            0);

  encrypted_sum = he_kit_.GetEvaluator()->SelectSum(
      encrypted_in2, std::vector<int64_t>{0, 1, 2}, std::vector<int64_t>{0});
  EXPECT_EQ(he_kit_.GetDecryptor()->Decrypt(encrypted_sum).GetValue<int64_t>(),
            1000000);
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

}  // namespace heu::lib::numpy::test
