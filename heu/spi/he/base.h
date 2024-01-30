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
#include <string>
#include <type_traits>
#include <vector>

#include "yacl/utils/spi/argument/arg_set.h"
#include "yacl/utils/spi/item.h"

namespace heu::lib::spi {

enum ItemType : uint8_t { Ciphertext, Plaintext };

class Item : public yacl::Item {
 public:
  // T should be scalar.
  // If T is container, call Item::Ref() or Item::Take() instead.
  template <typename T>
  constexpr Item(T&& value, ItemType cipher_or_plain)
      : yacl::Item(std::forward<T>(value)) {
    MarkAs(cipher_or_plain);
  }

  // Ref a vector/span
  template <typename T, typename _ = std::enable_if_t<yacl::is_container_v<T>>>
  static Item Ref(T& c, ItemType cipher_or_plain) {
    return Item{absl::MakeSpan(c), cipher_or_plain};
  }

  template <typename T>
  static Item Ref(T* ptr, size_t len, ItemType cipher_or_plain) {
    return Item{absl::MakeSpan(ptr, len), cipher_or_plain};
  }

  // Take vector
  template <typename T>
  static Item Take(std::vector<T>&& v, ItemType cipher_or_plain) {
    return Item{std::move(v), cipher_or_plain};
  }

  template <typename T>
  static Item EmptyVector(ItemType cipher_or_plain = ItemType::Plaintext) {
    return Item{std::vector<T>(), cipher_or_plain};
  }

  void operator=(yacl::Item&&) = delete;
  void operator=(const yacl::Item&) = delete;

  void MarkAs(ItemType cipher_or_plain);
  void MarkAsCiphertext();
  void MarkAsPlaintext();

  bool IsPlaintext() const;
  bool IsCiphertext() const;

  std::string ToString() const;
};

using SpiArgs = yacl::SpiArgs;

}  // namespace heu::lib::spi
