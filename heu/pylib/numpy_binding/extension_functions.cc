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

#include "heu/pylib/numpy_binding/extension_functions.h"

#include <tuple>

#include "fmt/ranges.h"
#include "yacl/utils/parallel.h"

#include "heu/library/numpy/matrix.h"
#include "heu/pylib/common/traits.h"
#include "heu/pylib/numpy_binding/slice_tool.h"

namespace heu::pylib {

// todo: place make sure this function is thread safe.
template <typename T>
T ExtensionFunctions<T>::SelectSum(const hnp::Evaluator& evaluator,
                                   const hnp::DenseMatrix<T>& p_matrix,
                                   const py::object& key) {
  if (py::isinstance<py::tuple>(key)) {
    auto idx_tuple = py::cast<py::tuple>(key);

    YACL_ENFORCE(static_cast<int64_t>(idx_tuple.size()) <= p_matrix.ndim(),
                 "too many indices for array, array is {}-dimensional, but "
                 "{} were indexed. slice key={}",
                 p_matrix.ndim(), idx_tuple.size(),
                 static_cast<std::string>(py::str(key)));

    if (idx_tuple.size() == 2) {
      // key id 2d and tensor is 2d
      bool sq_row, sq_col;
      auto s_row = slice_tool::Parse(idx_tuple[0], p_matrix.rows(), &sq_row);
      auto s_col = slice_tool::Parse(idx_tuple[1], p_matrix.cols(), &sq_col);

      return evaluator.SelectSum(p_matrix, s_row.indices, s_col.indices);
    }

    // break if: continue to process 1-d case
  }

  // key is 1d and tensor is 1d or 2d
  // key dimension is less than tensor dimension
  bool sq_row;
  auto s_row = slice_tool::Parse(key, p_matrix.rows(), &sq_row);
  return evaluator.SelectSum(p_matrix, s_row.indices, Eigen::placeholders::all);
}

namespace {

// we move this function here to avoid gcc warning:
//    '<lambda(int64_t, int64_t)>' declared with greater visibility than the
//    type of its field '<lambda(int64_t, int64_t)>::<key capture>'
template <typename T>
hnp::DenseMatrix<T> DoBatchSelectSum(const hnp::Evaluator& evaluator,
                                     const hnp::DenseMatrix<T>& p_matrix,
                                     const std::vector<py::object>& key) {
  auto res = hnp::DenseMatrix<T>(key.size());
  yacl::parallel_for(0, key.size(), 1, [&](int64_t beg, int64_t end) {
    for (int64_t x = beg; x < end; ++x) {
      res.data()[x] =
          ExtensionFunctions<T>::SelectSum(evaluator, p_matrix, key[x]);
    }
  });
  return res;
}

}  // namespace

template <typename T>
hnp::DenseMatrix<T> ExtensionFunctions<T>::BatchSelectSum(
    const hnp::Evaluator& evaluator, const hnp::DenseMatrix<T>& p_matrix,
    const std::vector<py::object>& key) {
  return DoBatchSelectSum(evaluator, p_matrix, key);
}

template <typename T>
lib::numpy::DenseMatrix<T> ExtensionFunctions<T>::FeatureWiseBucketSum(
    const lib::numpy::Evaluator& e, const lib::numpy::DenseMatrix<T>& x,
    const Eigen::Ref<RowVector>& subgroup_map,
    const Eigen::Ref<RowMatrixXd>& order_map, int bucket_num, bool cumsum) {
  auto total_bucket_num = bucket_num * order_map.cols();
  auto res = hnp::DenseMatrix<T>(total_bucket_num, x.cols());
  std::vector<size_t> subgroup_indices;
  for (auto j = 0; j < subgroup_map.size(); ++j) {
    if (subgroup_map[j] > 0) {
      subgroup_indices.push_back(j);
    }
  }
  e.FeatureWiseBucketSumInplace(
      x.GetItem(subgroup_indices, Eigen::placeholders::all),
      order_map(subgroup_indices, Eigen::placeholders::all), bucket_num, res,
      cumsum);
  return res;
}

template <typename T>
std::vector<lib::numpy::DenseMatrix<T>>
ExtensionFunctions<T>::BatchFeatureWiseBucketSum(
    const lib::numpy::Evaluator& e, const lib::numpy::DenseMatrix<T>& x,
    const std::vector<Eigen::Ref<RowVector>>& subgroup_maps,
    const Eigen::Ref<RowMatrixXd>& order_map, int bucket_num, bool cumsum) {
  auto total_bucket_num = bucket_num * order_map.cols();
  auto group_number = subgroup_maps.size();
  auto res = std::vector<hnp::DenseMatrix<T>>(
      group_number, hnp::DenseMatrix<T>(total_bucket_num, x.cols()));

  std::vector<std::vector<size_t>> subgroup_indices(group_number);

  yacl::parallel_for(0, group_number, 1, [&](int64_t beg, int64_t end) {
    for (auto i = beg; i < end; ++i) {
      subgroup_indices[i].reserve(subgroup_maps[i].size() / group_number);
      for (auto j = 0; j < subgroup_maps[i].size(); ++j) {
        if (subgroup_maps[i][j] > 0) {
          subgroup_indices[i].push_back(j);
        }
      }
    }
  });
  T zero = e.GetZero(x);
  for (size_t subgroup_index = 0; subgroup_index < group_number;
       ++subgroup_index) {
    if (subgroup_indices[subgroup_index].size() > 0) {
      e.FeatureWiseBucketSumInplace(
          x.GetItem(subgroup_indices[subgroup_index], Eigen::placeholders::all),
          order_map(subgroup_indices[subgroup_index], Eigen::placeholders::all),
          bucket_num, res[subgroup_index], cumsum);
    } else {
      auto buf = res[subgroup_index].data();
      yacl::parallel_for(0, total_bucket_num * x.cols(), 1,
                         [&](int64_t beg, int64_t end) {
                           for (auto i = beg; i < end; ++i) {
                             buf[i] = zero;
                           }
                         });
    }
  }
  return res;
}

template class ExtensionFunctions<lib::phe::Plaintext>;
template class ExtensionFunctions<lib::phe::Ciphertext>;

RowMatrixXd PureNumpyExtensionFunctions::TreePredict(
    const Eigen::Ref<RowMatrixXdDouble> x,
    const std::vector<int>& split_features,
    const std::vector<double>& split_points) {
  auto split_node_num = split_features.size();
  Eigen::Matrix<int8_t, -1, -1> res =
      Eigen::Matrix<int8_t, -1, -1>::Zero(x.rows(), split_node_num + 1);
  yacl::parallel_for(0, x.rows(), 32, [&](int64_t beg, int64_t end) {
    for (auto i = beg; i < end; ++i) {
      std::deque<size_t> idxs;
      idxs.push_back(0);

      while (idxs.size() > 0) {
        auto idx = idxs[0];
        idxs.pop_front();
        if (idx < split_node_num) {
          auto f = split_features[idx];
          auto v = split_points[idx];
          if (f == -1) {
            idxs.push_back(idx * 2 + 1);
            idxs.push_back(idx * 2 + 2);
          } else {
            if (x(i, f) < v) {
              idxs.push_back(idx * 2 + 1);
            } else {
              idxs.push_back(idx * 2 + 2);
            }
          }
        } else {
          auto leaf_idx = idx - split_node_num;
          res(i, leaf_idx) = 1;
        }
      }
    }
  });
  return res;
}

typedef std::tuple<int, double> NodeContent;
typedef std::unordered_map<int, NodeContent> SplitTree;

namespace {
SplitTree BuildTreeMap(const std::vector<int>& split_features,
                       const std::vector<double>& split_points,
                       const std::vector<int>& node_indices) {
  YACL_ENFORCE_EQ(node_indices.size(), split_features.size(),
                  "node length must be well defined");
  YACL_ENFORCE_EQ(node_indices.size(), split_points.size(),
                  "node length must be well defined");
  SplitTree res;
  for (size_t i = 0; i < node_indices.size(); ++i) {
    res[node_indices[i]] = NodeContent(split_features[i], split_points[i]);
  }
  return res;
}
}  // namespace

RowMatrixXd PureNumpyExtensionFunctions::TreePredictWithIndices(
    const Eigen::Ref<RowMatrixXdDouble> x,
    const std::vector<int>& split_features,
    const std::vector<double>& split_points,
    const std::vector<int>& node_indices,
    const std::vector<int>& leaf_indices) {
  auto split_node_num = split_features.size();
  YACL_ENFORCE_EQ(split_node_num + 1, leaf_indices.size(),
                  "leaf number must be well defined");
  // mathematical fact: leaf number = split points + 1
  Eigen::Matrix<int8_t, -1, -1> res =
      Eigen::Matrix<int8_t, -1, -1>::Zero(x.rows(), leaf_indices.size());
  auto split_tree = BuildTreeMap(split_features, split_points, node_indices);
  std::unordered_map<int, int> leaf_index_map;
  for (size_t i = 0; i < leaf_indices.size(); ++i) {
    leaf_index_map[leaf_indices[i]] = i;
  }
  yacl::parallel_for(0, x.rows(), 32, [&](int64_t beg, int64_t end) {
    for (auto i = beg; i < end; ++i) {
      std::deque<size_t> idxs;
      idxs.push_back(0);
      while (idxs.size() > 0) {
        auto idx = idxs[0];
        idxs.pop_front();
        if (split_tree.count(idx) > 0) {
          const NodeContent& node = split_tree[idx];
          int f = std::get<0>(node);
          double v = std::get<1>(node);
          if (f == -1) {
            idxs.push_back(idx * 2 + 1);
            idxs.push_back(idx * 2 + 2);
          } else {
            if (x(i, f) < v) {
              idxs.push_back(idx * 2 + 1);
            } else {
              idxs.push_back(idx * 2 + 2);
            }
          }
        } else {
          auto leaf_idx = leaf_index_map.at(idx);
          res(i, leaf_idx) = 1;
        }
      }
    }
  });
  return res;
}

}  // namespace heu::pylib
