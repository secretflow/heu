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
#include <ostream>
#include <string>
#include <type_traits>
#include <vector>

#include "yacl/utils/spi/argument/arg_set.h"
#include "yacl/utils/spi/item.h"

namespace heu::lib::spi {

enum class ContentType : uint8_t {
  Others = 0,
  Plaintext = 1,
  Ciphertext = 2,
  SecretKey = 3,
  PublicKey = 4,
  RelinKeys = 5,
  GaloisKeys = 6,
  BootstrapKey = 7,
  /* DO NOT ADD NEW TYPE */
};

enum class HeKeyType : uint8_t {
  // C++ does not support enum inheritance,
  // please make sure that the number of HeKeyType strictly matches ContentType.
  SecretKey = 3,
  PublicKey = 4,
  RelinKeys = 5,
  GaloisKeys = 6,
  BootstrapKey = 7,
};

inline constexpr auto format_as(ContentType t) {
  switch (t) {
    case ContentType::Others:
      return "Other";
    case ContentType::Plaintext:
      return "Plaintext";
    case ContentType::Ciphertext:
      return "Ciphertext";
    case ContentType::SecretKey:
      return "SecretKey";
    case ContentType::PublicKey:
      return "PublicKey";
    case ContentType::RelinKeys:
      return "RelinKeys";
    case ContentType::GaloisKeys:
      return "GaloisKeys";
    case ContentType::BootstrapKey:
      return "BootstrapKey";
    default:
      return "Unknown type";
  }
}

inline constexpr auto format_as(HeKeyType kt) {
  return format_as(static_cast<ContentType>(kt));
}

class Item : public yacl::Item {
 public:
  // T should be scalar.
  // If T is container, call Item::Ref() or Item::Take() instead.
  template <typename T>
  constexpr Item(T&& value, ContentType type)
      : yacl::Item(std::forward<T>(value)) {
    MarkAs(type);
  }

  // Ref a vector/span
  template <typename T, typename _ = std::enable_if_t<yacl::is_container_v<T>>>
  static Item Ref(T& c, ContentType type) {
    return Item{absl::MakeSpan(c), type};
  }

  template <typename T>
  static Item Ref(T* ptr, size_t len, ContentType type) {
    return Item{absl::MakeSpan(ptr, len), type};
  }

  // Take vector
  template <typename T>
  static Item Take(std::vector<T>&& v, ContentType type) {
    return Item{std::move(v), type};
  }

  template <typename T>
  static Item EmptyVector(ContentType type = ContentType::Plaintext) {
    return Item{std::vector<T>(), type};
  }

  // prevent implicit convert yacl::Item to Item
  Item(const Item&) = default;
  Item(Item&&) = default;
  Item& operator=(const Item&) = default;
  Item& operator=(Item&&) = default;
  Item& operator=(yacl::Item&&) = delete;
  Item& operator=(const yacl::Item&) = delete;

  Item(const yacl::Item&) = delete;  // avoid copy construct

  Item(yacl::Item&& base, ContentType type) : yacl::Item(std::move(base)) {
    MarkAs(type);
  }

  void MarkAs(ContentType type);
  void MarkAsCiphertext();
  void MarkAsPlaintext();

  ContentType GetContentType() const;
  bool IsPlaintext() const;
  bool IsCiphertext() const;

  std::string ToString() const;
  friend std::ostream& operator<<(std::ostream& os, const Item& item);

  template <typename T>
  Item SubItem(size_t pos, size_t len = absl::Span<T>::npos) {
    return {yacl::Item::SubItem<T>(pos, len), GetContentType()};
  }

  template <typename T>
  Item SubItem(size_t pos, size_t len = absl::Span<T>::npos) const {
    return {yacl::Item::SubItem<T>(pos, len), GetContentType()};
  }
};

inline auto format_as(const Item& item) { return item.ToString(); }

// ===  THE MSGPACK SERIALIZE FORMAT === //
// | 1bytes header | body |
// header: store content type of item
// body: depends on if item is an array
// - Scalar: |STR len| serialized buffer |
// - Vector: |ARRAY len|STR len|element-1 buf|STR len|element-2 buf|...

using SpiArgs = yacl::SpiArgs;

}  // namespace heu::lib::spi
