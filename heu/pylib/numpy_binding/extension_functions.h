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

#include "heu/library/numpy/eigen_traits.h"
// keep eigen_traits.h in first line

#include "pybind11/eigen.h"
#include "pybind11/pybind11.h"

#include "heu/library/numpy/evaluator.h"
#include "heu/library/numpy/matrix.h"

namespace heu::pylib {
using RowMatrixXd = const Eigen::Matrix<int8_t, Eigen::Dynamic, Eigen::Dynamic,
                                        Eigen::RowMajor>;
using RowMatrixXdDouble = const Eigen::Matrix<double_t, Eigen::Dynamic,
                                              Eigen::Dynamic, Eigen::RowMajor>;
using RowVector = const Eigen::Matrix<int8_t, 1, Eigen::Dynamic>;

template <typename T>
class ExtensionFunctions {
 public:
  static T SelectSum(const lib::numpy::Evaluator& e,
                     const lib::numpy::DenseMatrix<T>& x,
                     const pybind11::object& key);

  static lib::numpy::DenseMatrix<T> BatchSelectSum(
      const lib::numpy::Evaluator& e, const lib::numpy::DenseMatrix<T>& x,
      const std::vector<pybind11::object>& key);

  /// @brief Take elements in x according to order_map to caculate the row sum
  /// at each bin.
  /// @tparam T Plaintext or Ciphertext
  /// @param e heu numpy evaluator
  /// @param x dense matrix, rows are elements of bin sum
  /// @param subgroup_map a 1d py np ndarray (vector) acts as a filter. Its
  /// length should be equal to x.rows(), elements should be 0 or 1, with 1
  /// indicates in this subgroup.
  /// @param order_map a 2d py ndarray. It has shape x.rows() * number of
  /// features.order_map(i, j) = k means row i feature j should be in bin k of
  /// feature j.
  /// @param bucket_num int. The number of buckets for each bin.
  /// @param cumsum bool. if apply cum sum to buckets for earch feature.
  /// @return dense matrix<T>, the row bin sum result. It has shape (bucket_num
  /// * feature_num, x.cols()).
  static lib::numpy::DenseMatrix<T> FeatureWiseBucketSum(
      const lib::numpy::Evaluator& e, const lib::numpy::DenseMatrix<T>& x,
      const Eigen::Ref<RowVector>& subgroup_map,
      const Eigen::Ref<RowMatrixXd>& order_map, int bucket_num,
      bool cumsum = false);

  /// @brief Take elements in x according to order_map to caculate the row sum
  /// at
  /// each bin for each subgroup.
  /// @tparam T Plaintext or Ciphertext
  /// @param e heu numpy evaluator
  /// @param x dense matrix, rows are elements of bin sum
  /// @param subgroup_map a list of 1d py np ndarray (vector) acts as filters.
  /// Each element's length should be equal to x.rows(), elements should be 0 or
  /// 1, with 1 indicates in this subgroup.
  /// @param order_map a 2d py ndarray. It has shape x.rows() * number of
  /// features.order_map(i, j) = k means row i feature j should be in bin k of
  /// feature j.
  /// @param bucket_num int. The number of buckets for each bin.
  /// @param cumsum bool. if apply cum sum to buckets for earch feature.
  /// @return a list of dense matrix<T>, the row bin sum result. Each element
  /// has shape (bucket_num * feature_num, x.cols()).
  static std::vector<lib::numpy::DenseMatrix<T>> BatchFeatureWiseBucketSum(
      const lib::numpy::Evaluator& e, const lib::numpy::DenseMatrix<T>& x,
      const std::vector<Eigen::Ref<RowVector>>& subgroup_maps,
      const Eigen::Ref<RowMatrixXd>& order_map, int bucket_num,
      bool cumsum = false);
};

// Pure xgb logic that should be in another library
class PureNumpyExtensionFunctions {
 public:
  // tree predict based on split features and points
  // return shape is constant np array of size x.rows() *
  // split_features.size()+1
  static RowMatrixXd TreePredict(const Eigen::Ref<RowMatrixXdDouble> x,
                                 const std::vector<int>& split_features,
                                 const std::vector<double>& split_points);

  /// @brief unbalanced tree prediction
  /// @param x
  /// @param split_features
  /// @param split_points
  /// @param node_indices indices corresponds to split nodes.
  /// @param leaf_indices indices of leaves
  /// @return indicator map of shape (x.rows(), leaf_number)
  static RowMatrixXd TreePredictWithIndices(
      const Eigen::Ref<RowMatrixXdDouble> x,
      const std::vector<int>& split_features,
      const std::vector<double>& split_points,
      const std::vector<int>& node_indices,
      const std::vector<int>& leaf_indices);
};
}  // namespace heu::pylib
