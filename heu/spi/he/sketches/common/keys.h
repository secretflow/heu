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

  // 我们非常推荐您在子类中实现以下函数，如果不实现，则需要在 HeKit 实现 Key
  // 的序列化函数。
  // We highly recommend that you implement the following functions
  // in the subclass. If not, you will need to implement the Key serialization
  // function in HeKit.
  //
  // size_t Serialize(uint8_t *buf, size_t buf_len) const;
};

template <HeKeyType key_type>
class EmptyKeySketch : public KeySketch<key_type> {
 public:
  std::map<std::string, std::string> ListParams() const override { return {}; }

  // nothing to serialize
  size_t Serialize(uint8_t *, size_t) const { return 0; };
};

}  // namespace heu::spi
