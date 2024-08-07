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

#include "heu/library/phe/base/serializable_types.h"

#include <experimental/type_traits>

#include "heu/library/phe/base/variant_helper.h"

namespace heu::lib::phe {

#define HE_EMPLACE_INSTANCE(ns, clazz) (ns::clazz())
#define DEFINITION_VTABLE(clazz)                                             \
  template <>                                                                \
  const std::variant<std::monostate, HE_NAMESPACE_LIST(clazz)>               \
      SerializableVariant<HE_NAMESPACE_LIST(clazz)>::schema2ns_vtable_[] = { \
          HE_FOR_EACH(HE_EMPLACE_INSTANCE, clazz)}

// Define static variable `schema2ns_vtable_`
DEFINITION_VTABLE(Ciphertext);
DEFINITION_VTABLE(PublicKey);
DEFINITION_VTABLE(SecretKey);

template <>
const std::variant<std::monostate, HE_PLAINTEXT_TYPES>
    SerializableVariant<HE_PLAINTEXT_TYPES>::schema2ns_vtable_[] = {
        HE_FOR_EACH(HE_EMPLACE_INSTANCE, Plaintext)};

template <typename... Types>
SerializableVariant<Types...>::SerializableVariant(SchemaType schema_type) {
  var_ = schema2ns_vtable_[Schema2NamespaceIdx(schema_type)];
}

template <typename T>
using kHasSerializeWithMetaMethod =
    decltype(std::declval<T &>().Serialize(std::declval<bool &>()));

template <typename... Types>
yacl::Buffer SerializableVariant<Types...>::Serialize(bool with_meta) const {
  yacl::Buffer payload = Visit([with_meta](const auto &clazz) -> yacl::Buffer {
    FOR_EACH_TYPE(clazz) {
      if constexpr (std::experimental::is_detected_v<
                        kHasSerializeWithMetaMethod, decltype(clazz)>) {
        return clazz.Serialize(with_meta);
      } else {
        return clazz.Serialize();
      }
    }
  });
  uint8_t idx = GetAlignedIdx();

  // Append idx to the end of payload to reduce memory copying
  auto payload_sz = payload.size();
  payload.resize(static_cast<int64_t>(payload_sz + sizeof(idx)));
  *reinterpret_cast<uint8_t *>(payload.data<uint8_t>() + payload_sz) = idx;
  return payload;
}

template <typename... Types>
uint8_t SerializableVariant<Types...>::GetAlignedIdx() const {
  // -1 for std::monostate
  return static_cast<uint8_t>((NamespaceIdx2Schema(var_.index() - 1)));
}

template <>
uint8_t SerializableVariant<HE_PLAINTEXT_TYPES>::GetAlignedIdx() const {
  return var_.index();
}

template <typename... Types>
void SerializableVariant<Types...>::EmplaceInstance(uint8_t aligned_idx) {
  var_ = schema2ns_vtable_[Schema2NamespaceIdx(
      static_cast<SchemaType>(aligned_idx))];
}

// for Plaintext type
template <typename Variant, typename T, typename... Ts,
          std::size_t current_index, std::size_t... indices>
Variant NewVariantByIdx(std::size_t index,
                        std::index_sequence<current_index, indices...>) {
  if constexpr (sizeof...(Ts) == 0) {
    return Variant{std::in_place_index<current_index>};
  } else {
    if (index == current_index) {
      return Variant{std::in_place_index<current_index>};
    }
    return NewVariantByIdx<Variant, Ts...>(index,
                                           std::index_sequence<indices...>());
  }
}

// for Plaintext type
template <>
void SerializableVariant<HE_PLAINTEXT_TYPES>::EmplaceInstance(
    uint8_t aligned_idx) {
  constexpr size_t max_idx = std::variant_size_v<decltype(var_)>;
  var_ = NewVariantByIdx<decltype(var_), std::monostate, HE_PLAINTEXT_TYPES>(
      aligned_idx, std::make_index_sequence<max_idx>());
}

template <typename... Types>
void SerializableVariant<Types...>::Deserialize(yacl::ByteContainerView in) {
  YACL_ENFORCE(in.size() > sizeof(uint8_t), "Illegal buffer size {}",
               in.size());

  uint8_t idx = *reinterpret_cast<const uint8_t *>(in.data() + in.size() -
                                                   sizeof(uint8_t));
  yacl::ByteContainerView payload(in.data(), in.size() - sizeof(uint8_t));

  EmplaceInstance(idx);
  Visit([&](auto &clazz) { FOR_EACH_TYPE(clazz) clazz.Deserialize(payload); });
}

template <typename... Types>
bool SerializableVariant<Types...>::IsCompatible(SchemaType schema_type) const {
  return var_.index() ==
         schema2ns_vtable_[Schema2NamespaceIdx(schema_type)].index();
}

template <typename... Types>
std::string SerializableVariant<Types...>::ToString() const {
  return Visit(Overloaded{
      // the std::monostate is also stringable, so we don't use FOR_EACH_TYPE
      [](const std::monostate &) {
        return std::string("<uninitialized variable (no schema info)>");
      },
      [](const auto &clazz) -> std::string { return clazz.ToString(); }});
}

template class SerializableVariant<HE_NAMESPACE_LIST(SecretKey)>;
template class SerializableVariant<HE_NAMESPACE_LIST(PublicKey)>;
template class SerializableVariant<HE_NAMESPACE_LIST(Ciphertext)>;
template class SerializableVariant<HE_PLAINTEXT_TYPES>;

}  // namespace heu::lib::phe
