// Copyright 2024 Ant Group Co., Ltd.
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

#include <map>
#include <string>

#include "heu/spi/he/item.h"

namespace heu::spi {

namespace internal {
std::string FormatKey(HeKeyType key_type,
                      const std::map<std::string, std::string> &params);
}

template <HeKeyType key_type>
class KeySketch {
 public:
  virtual ~KeySketch() = default;

  // get the params of a key
  // return: a map of <param_name, param_value>, all values are converted to
  // string.
  // e.g., Paillier secretkey returns {p=xxx, q=xxx}
  virtual std::map<std::string, std::string> ListParams() const = 0;

  virtual std::string ToString() const {
    return internal::FormatKey(key_type, ListParams());
  }
};

template <HeKeyType key_type>
class EmptyKeySketch : public KeySketch<key_type> {
 public:
  std::map<std::string, std::string> ListParams() const override { return {}; }
};

}  // namespace heu::spi
