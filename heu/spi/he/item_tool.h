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

#include <cstddef>
#include <cstdint>
#include <string>

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"

#include "heu/spi/he/item.h"

namespace heu::spi {

// ItemTool implements a set of tools for operating on Item objects.
//
// All methods support Items in the following form:
// 1. Plaintext
// 2. Plaintext array
// 3. Ciphertext
// 4. Ciphertext array
class ItemTool {
 public:
  virtual ~ItemTool() = default;

  //===   Item operations   ===//

  virtual size_t ItemSize(const Item &item) const = 0;

  virtual Item SubItem(const Item &item, size_t pos) const = 0;
  virtual Item SubItem(Item &item, size_t pos) const = 0;
  virtual Item SubItem(const Item &item, size_t pos, size_t len) const = 0;
  virtual Item SubItem(Item &item, size_t pos, size_t len) const = 0;

  // append item2 to the tail of item1
  virtual void AppendItem(Item *item1, const Item &item2) const = 0;
  virtual Item CombineItem(const Item &item1, const Item &item2) const = 0;

  // Make a deep copy of obj.
  // Note: Cannot clone keys
  virtual Item Clone(const Item &item) const = 0;

  // Convert Item to a human-readable string.
  // The item can be:
  //   1. Plaintext
  //   2. Plaintext array
  //   3. Ciphertext
  //   4. Ciphertext array
  //   5. All kinds of keys
  virtual std::string ToString(const Item &item) const = 0;

  // todo: We need more interfaces to precisely control the internal state of
  // the ciphertext.
  // Maybe we need a interface to read/write attributes of PT/CT

  // Check two items are equal
  virtual bool Equal(const Item &x, const Item &y) const = 0;

  //===   I/O for HE Objects   ===//

  // Serialize HE objects (plaintext(s) and ciphertext(s)) to buffer.
  // Note: Do not support ser/deser keys
  virtual yacl::Buffer Serialize(const Item &item) const = 0;
  // Serialize HE objects to already allocated buffer.
  // If buf is nullptr, then calc approximate serialize size only.
  // And the approximate size is always larger than actual size.
  // @return: the actual size of serialized buffer
  virtual size_t Serialize(const Item &item, uint8_t *buf,
                           size_t buf_len) const = 0;

  virtual Item Deserialize(yacl::ByteContainerView buffer) const = 0;
};

}  // namespace heu::spi
