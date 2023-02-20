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

#include "heu/library/numpy/matrix.h"
#include "heu/pylib/common/traits.h"

// These functions help to deal with slicing in python
namespace heu::pylib {
namespace slice_tool {
// record one dim's slice info
template <typename INDICES_T>
struct PySlice {
  ssize_t items;
  INDICES_T indices;
  std::string ToString() { return fmt::format("PySlice index {}", indices); }
};

// convert src from a python style index to a valid C++ array index
// check src < dim_len
// if src < 0, compute y such that y = dim_len - src
int64_t ComputeInt(const py::handle& src, int64_t dim_len);

// parse the python slice info into a PySlice struct.
PySlice<std::vector<int64_t>> Parse(const pybind11::object& src,
                                    ssize_t dim_len,
                                    bool* should_squeeze = nullptr);

// express python slice [:] in PySlice struct.
auto All(ssize_t dim_len) -> PySlice<decltype(Eigen::all)>;

}  // namespace slice_tool

}  // namespace heu::pylib