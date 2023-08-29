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
#include <variant>

#include "yacl/base/byte_container_view.h"

#include "heu/library/phe/base/schema.h"

namespace heu::lib::phe {

// Check type T in Ts list
template <typename T, typename... Ts>
struct type_in
    : std::disjunction<
          std::is_same<std::remove_cv_t<std::remove_reference_t<T>>, Ts>...> {};

template <class... T>
inline constexpr bool type_in_v = type_in<T...>::value;

template <typename T, typename... Ts>
struct peel_type
    : std::enable_if_t<type_in_v<T, Ts...>,
                       std::remove_cv<std::remove_reference_t<T>>> {};

template <typename... Ts>
using peel_type_t = typename peel_type<Ts...>::type;

// There are some compilation issues if directly inherit from std::variant,
// so we use combination method currently.
template <typename... Types>
class SerializableVariant {
 public:
  template <typename T, std::enable_if_t<type_in_v<T, Types...>, int> = 0>
  explicit SerializableVariant(T &&value) : var_(std::forward<T>(value)) {}

  explicit SerializableVariant(SchemaType schema_type);

  SerializableVariant() noexcept = default;
  SerializableVariant(const SerializableVariant &ct) = default;
  SerializableVariant(SerializableVariant &&ct) noexcept = default;

  SerializableVariant &operator=(const SerializableVariant &other) = default;
  SerializableVariant &operator=(SerializableVariant &&other) noexcept =
      default;

  // convert and assign
  template <typename T, std::enable_if_t<type_in_v<T, Types...>, int> = 0>
  SerializableVariant &operator=(T &&value) {
    var_ = std::forward<T>(value);
    return *this;
  }

  bool IsCompatible(SchemaType schema_type) const;

  template <class T>
  bool IsHoldType() const {
    return std::holds_alternative<T>(var_);
  }

  template <typename T>
  constexpr peel_type_t<T, Types...> &As() & {
    return std::get<peel_type_t<T, Types...>>(var_);
  };

  template <typename T>
  constexpr peel_type_t<T, Types...> &&As() && {
    return std::get<peel_type_t<T, Types...>>(std::move(var_));
  };

  template <typename T>
  constexpr const peel_type_t<T, Types...> &As() const {
    return std::get<peel_type_t<T, Types...>>(var_);
  };

  template <typename T, std::enable_if_t<type_in_v<T, Types...>, int> = 0>
  constexpr const peel_type_t<T, Types...> &AsTypeLike(
      const T & /*like*/) const {
    return As<T>();
  };

  template <typename T, std::enable_if_t<type_in_v<T, Types...>, int> = 0>
  constexpr peel_type_t<T, Types...> &AsTypeLike(T & /*like*/) {
    return As<T>();
  };

  template <typename T, std::enable_if_t<type_in_v<T, Types...>, int> = 0>
  constexpr peel_type_t<T, Types...> *AsTypeLike(T * /*like*/) {
    return &As<T>();
  };

  // Please make sure SchemaType is set before calling visit()
  template <class Visitor>
  constexpr decltype(auto) Visit(Visitor &&vis) {
    return std::visit(std::forward<Visitor>(vis), var_);
  }

  // Please make sure SchemaType is set before calling visit()
  template <class Visitor>
  constexpr decltype(auto) Visit(Visitor &&vis) const {
    return std::visit(std::forward<Visitor>(vis), var_);
  }

  bool operator==(const SerializableVariant &other) const {
    return var_ == other.var_;
  }

  bool operator!=(const SerializableVariant &other) const {
    return var_ != other.var_;
  }

  [[nodiscard]] yacl::Buffer Serialize(bool with_meta = false) const;
  void Deserialize(yacl::ByteContainerView clazz);
  [[nodiscard]] std::string ToString() const;

  friend std::ostream &operator<<(std::ostream &os,
                                  const SerializableVariant<Types...> &obj) {
    return os << obj.ToString();
  }

 protected:
  void EmplaceInstance(size_t idx);

  std::variant<std::monostate, Types...> var_;
  const static std::variant<std::monostate, Types...> schema2ns_vtable_[];
};

using MPInt = algorithms::MPInt;
using Ciphertext = SerializableVariant<HE_NAMESPACE_LIST(Ciphertext)>;

template <typename... Types>
inline auto format_as(const SerializableVariant<Types...> &i) {
  return fmt::streamed(i);
}

}  // namespace heu::lib::phe
