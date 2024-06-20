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

#include <cstdlib>
#include <string>

#include "msgpack.hpp"
#include "yacl/base/byte_container_view.h"

namespace heu::lib::algorithms {

template <typename T>
class HeObject {
 protected:
  HeObject() = default;
  virtual ~HeObject() = default;

 public:
  [[nodiscard]] yacl::Buffer Serialize() const {
    msgpack::sbuffer buffer;
    msgpack::pack(buffer, *static_cast<const T *>(this));
    auto sz = buffer.size();
    return {buffer.release(), sz, [](void *ptr) { free(ptr); }};
  }

  void Deserialize(yacl::ByteContainerView in) {
    auto msg =
        msgpack::unpack(reinterpret_cast<const char *>(in.data()), in.size());
    msgpack::object obj = msg.get();
    obj.convert(*static_cast<T *>(this));
  }

  [[nodiscard]] virtual std::string ToString() const = 0;
};

}  // namespace heu::lib::algorithms
