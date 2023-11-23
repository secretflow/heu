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
