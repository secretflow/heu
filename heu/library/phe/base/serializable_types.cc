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
  var_ = schema2ns_vtable_[static_cast<int>(schema_type)];
}

template <typename... Types>
yacl::Buffer SerializableVariant<Types...>::Serialize() const {
  yacl::Buffer payload = Visit([](const auto &clazz) -> yacl::Buffer {
    FOR_EACH_TYPE(clazz) { return clazz.Serialize(); }
  });
  size_t idx = var_.index();

  // Append idx to the end of payload to reduce memory copying
  auto payload_sz = payload.size();
  payload.resize(static_cast<int64_t>(payload_sz + sizeof(idx)));
  *reinterpret_cast<size_t *>(payload.data<uint8_t>() + payload_sz) = idx;
  return payload;
}

#define EMPLACE_CASE(n)                         \
  case n:                                       \
    if constexpr (max_idx >= (n)) {             \
      var_.template emplace<n>();               \
    } else {                                    \
      YACL_THROW("Bug: illegal variant index"); \
    }                                           \
    break

template <typename... Types>
void SerializableVariant<Types...>::EmplaceInstance(size_t idx) {
  // total types: Types + monostate
  constexpr size_t max_idx = sizeof...(Types);
  static_assert(max_idx <= 6,
                "For developer: please add more switch-case branches");

  switch (idx) {  // O(n)
    EMPLACE_CASE(0);
    EMPLACE_CASE(1);
    EMPLACE_CASE(2);
    EMPLACE_CASE(3);
    EMPLACE_CASE(4);
    EMPLACE_CASE(5);
    EMPLACE_CASE(6);
    default:
      YACL_THROW("Bug: please contact developers to fix problem");
  }
}

template <typename... Types>
void SerializableVariant<Types...>::Deserialize(yacl::ByteContainerView in) {
  YACL_ENFORCE(in.size() > sizeof(size_t), "Illegal buffer size {}", in.size());

  size_t idx =
      *reinterpret_cast<const size_t *>(in.data() + in.size() - sizeof(size_t));
  yacl::ByteContainerView payload(in.data(), in.size() - sizeof(size_t));

  EmplaceInstance(idx);
  Visit([&](auto &clazz) { FOR_EACH_TYPE(clazz) clazz.Deserialize(payload); });
}

template <typename... Types>
bool SerializableVariant<Types...>::IsCompatible(SchemaType schema_type) const {
  return var_.index() ==
         schema2ns_vtable_[static_cast<int>(schema_type)].index();
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
