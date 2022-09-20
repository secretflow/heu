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

#include "yasl/base/byte_container_view.h"

#include "heu/library/phe/schema.h"

namespace heu::lib::phe {

// There are some compilation issues if directly inherit from std::variant,
// so we use combination method currently.
template <typename... Types>
class SerializableVariant {
 public:
  template <typename T>
  explicit SerializableVariant(T &&t) : var_(std::forward<T>(t)) {}
  explicit SerializableVariant(SchemaType schema_type);

  SerializableVariant() noexcept = default;
  SerializableVariant(const SerializableVariant &ct) = default;
  SerializableVariant(SerializableVariant &&ct) noexcept = default;

  SerializableVariant &operator=(const SerializableVariant &other) = default;
  SerializableVariant &operator=(SerializableVariant &&other) noexcept =
      default;

  template <typename T>
  constexpr T &get() {
    return std::get<T>(var_);
  };

  template <typename T>
  constexpr T &&get() && {
    return std::get<T>(std::move(var_));
  };

  template <typename T>
  constexpr const T &get() const {
    return std::get<T>(var_);
  };

  // Please make sure SchemaType is set before calling visit()
  template <class Visitor>
  constexpr decltype(auto) visit(Visitor &&vis) {
    return std::visit(std::forward<Visitor>(vis), var_);
  }

  // Please make sure SchemaType is set before calling visit()
  template <class Visitor>
  constexpr decltype(auto) visit(Visitor &&vis) const {
    return std::visit(std::forward<Visitor>(vis), var_);
  }

  bool operator==(const SerializableVariant &other) const {
    return var_ == other.var_;
  }

  bool operator!=(const SerializableVariant &other) const {
    return var_ != other.var_;
  }

  [[nodiscard]] yasl::Buffer Serialize() const;
  void Deserialize(yasl::ByteContainerView clazz);
  [[nodiscard]] std::string ToString() const;

  friend std::ostream &operator<<(std::ostream &os,
                                  const SerializableVariant<Types...> &obj) {
    return os << obj.ToString();
  }

 private:
  std::variant<Types...> var_;
  const static std::variant<Types...> schema2ns_vtable_[sizeof...(Types)];
};

using Plaintext = algorithms::Plaintext;
using Ciphertext = SerializableVariant<HE_NAMESPACE_LIST(Ciphertext)>;

using SecretKey = SerializableVariant<HE_NAMESPACE_LIST(SecretKey)>;

// using PublicKey = SerializableVariant<HE_NAMESPACE_LIST(PublicKey)>;
class PublicKey : public SerializableVariant<HE_NAMESPACE_LIST(PublicKey)> {
 public:
  using SerializableVariant<HE_NAMESPACE_LIST(PublicKey)>::SerializableVariant;

  // Valid plaintext range: (PlaintextBound(), -PlaintextBound())
  [[nodiscard]] const Plaintext &PlaintextBound() const & {
    return this->visit([](const auto &clazz) -> const Plaintext & {
      return clazz.PlaintextBound();
    });
  }
};

}  // namespace heu::lib::phe
