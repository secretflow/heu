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

#include <string>

#include "yacl/base/byte_container_view.h"

namespace heu::spi {

// 仅仅作为 Plaintext 和 Ciphertext 的模板提供，不要求 Lib 侧算法强制继承
// Provided only as a template for Plaintext and Ciphertext, without requiring
// mandatory inheritance for algorithms in LIBs.
template <typename SUB_CLAZZ>
class PtCtSketch {
 public:
  virtual ~PtCtSketch() = default;

  virtual std::string ToString() const = 0;

  virtual bool operator==(const SUB_CLAZZ &other) const = 0;

  virtual bool operator!=(const SUB_CLAZZ &other) const {
    return !this->operator==(other);
  }

  virtual size_t Serialize(uint8_t *, size_t) const {
    YACL_THROW(
        // 二选一：要么实现本方法，要么在 ItemTool 中实现 PT/CT 的序列化方法
        "Choose one of the two options: either override this method, or "
        "implement the serialization method in ItemTool");
  }

  virtual void Deserialize(yacl::ByteContainerView) {
    YACL_THROW(
        // 二选一：要么实现本方法，要么在 ItemTool 中实现 PT/CT 的反序列化方法
        "Choose one of the two options: either override this method, or "
        "implement the deserialization method in ItemTool");
  }
};

}  // namespace heu::spi
