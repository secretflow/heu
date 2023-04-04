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

#include "Eigen/Core"
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

  static lib::numpy::DenseMatrix<T> FeatureWiseBucketSum(
      const lib::numpy::Evaluator& e, const lib::numpy::DenseMatrix<T>& x,
      const Eigen::Ref<RowVector>& subgroup_map,
      const Eigen::Ref<RowMatrixXd>& order_map, int bucket_num,
      bool cumsum = false);

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
};

}  // namespace heu::pylib
