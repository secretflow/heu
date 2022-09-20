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

#include "fmt/format.h"
#include "fmt/ostream.h"
#include "msgpack.hpp"

namespace heu::lib::numpy {

class Shape : public algorithms::HeObject<Shape> {
 public:
  Shape(){}
  explicit Shape(std::vector<int64_t> shape) : shape_(std::move(shape)) {}
  Shape(std::initializer_list<int64_t> il) : shape_(il) {}

  int64_t Ndim() const { return static_cast<int64_t>(shape_.size()); }

  int64_t operator[](int64_t index) const {
    if (index < 0) {
      index += Ndim();
    }

    YASL_ENFORCE(0 <= index && index < Ndim(),
                 "index out of range, shape={}, index={}", ToString(), index);
    return shape_[index];
  }

  // alias for shape[0]
  // for dim-1 tensor, we store it in vertical vector
  [[nodiscard]] int64_t RowsAlloc() const {
    return !shape_.empty() ? shape_[0] : 1;
  }
  // alias for shape[1]
  [[nodiscard]] int64_t ColsAlloc() const {
    return shape_.size() > 1 ? shape_[1] : 1;
  }

  auto begin() const { return shape_.begin(); }
  auto end() const { return shape_.end(); }

  std::string ToString() const {
    return fmt::format("({})", fmt::join(shape_, ","));
  }

  friend std::ostream& operator<<(std::ostream& os, const Shape& s) {
    return os << s.ToString();
  }

  MSGPACK_DEFINE(shape_);

 private:
  std::vector<int64_t> shape_;
};

}  // namespace heu::lib::numpy
