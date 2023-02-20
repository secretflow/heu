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

#include "heu/pylib/numpy_binding/slice_tool.h"

#include "fmt/ranges.h"

namespace heu::pylib {

namespace slice_tool {

int64_t ComputeInt(const py::handle& src, int64_t dim_len) {
  auto idx = static_cast<int64_t>(py::cast<py::int_>(src));
  YACL_ENFORCE(idx < dim_len, "index {} is out of bounds [0, {})", idx,
               dim_len);
  if (idx < 0) {
    idx += dim_len;
    YACL_ENFORCE(idx >= 0, "index {} is out of bounds [{}, {})", idx - dim_len,
                 -dim_len, dim_len);
  }
  return idx;
}

PySlice<std::vector<int64_t>> Parse(const pybind11::object& src,
                                    ssize_t dim_len, bool* should_squeeze) {
  PySlice<std::vector<int64_t>> res;
  bool squeeze = false;
  if (py::isinstance<py::slice>(src)) {
    auto s = py::cast<py::slice>(src);
    ssize_t start = 0, stop = 0, step = 0;
    YACL_ENFORCE(s.compute(dim_len, &start, &stop, &step, &res.items),
                 "Failed to solve slice {}", py::str(s).operator std::string());

    // todo：use Eigen::seq
    res.indices.reserve(res.items);
    YACL_ENFORCE(step != 0, "slice step cannot be 0");
    if (step > 0) {
      for (; start < stop; start += step) {
        res.indices.push_back(start);
      }
    } else {
      for (; start > stop; start += step) {
        res.indices.push_back(start);
      }
    }
  }

  else if (py::isinstance<py::sequence>(src)) {
    auto l = py::cast<py::sequence>(src);
    res.items = l.size();
    res.indices.reserve(res.items);
    for (const auto& item : l) {
      YACL_ENFORCE(
          py::isinstance<py::int_>(item),
          "indices array element must be integers, got {} with type {}",
          std::string(py::str(item)), std::string(py::str(item.get_type())));
      res.indices.push_back(ComputeInt(item, dim_len));
    }

  } else if (py::isinstance<py::int_>(src)) {
    squeeze = true;
    res.items = 1;
    res.indices.push_back(ComputeInt(src, dim_len));

  } else {
    YACL_THROW_ARGUMENT_ERROR(
        "Unsupported indices type {}",
        static_cast<std::string>(py::str(src.get_type())));
  }

  if (should_squeeze != nullptr) {
    *should_squeeze = squeeze;
  }
  return res;
}

auto All(ssize_t dim_len) -> PySlice<decltype(Eigen::all)> {
  return {dim_len, Eigen::all};
};

}  // namespace slice_tool
}  // namespace heu::pylib
