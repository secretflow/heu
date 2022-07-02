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

#include "heu/library/phe/serializable_types.h"

namespace heu::lib::phe {

#define HE_EMPLACE_INSTANCE(ns, clazz) (ns::clazz())
#define DEFINITION_VTABLE(clazz)                                             \
  template <>                                                                \
  const std::variant<HE_NAMESPACE_LIST(clazz)>                               \
      SerializableVariant<HE_NAMESPACE_LIST(clazz)>::schema2ns_vtable_[] = { \
          HE_FOR_EACH(HE_EMPLACE_INSTANCE, clazz)}

// Define static variable `schema2ns_vtable_`
DEFINITION_VTABLE(Ciphertext);
DEFINITION_VTABLE(PublicKey);
DEFINITION_VTABLE(SecretKey);

template <typename... Types>
SerializableVariant<Types...>::SerializableVariant(SchemaType schema_type) {
  var_ = schema2ns_vtable_[static_cast<int>(schema_type)];
}

template <typename... Types>
yasl::Buffer SerializableVariant<Types...>::Serialize() const {
  yasl::Buffer payload = std::visit(
      [](const auto &clazz) { return clazz.Serialize(); }, this->var_);
  size_t idx = var_.index();

  // Append idx to the end of payload to reduce memory copying
  auto payload_sz = payload.size();
  payload.resize(static_cast<int64_t>(payload_sz + sizeof(idx)));
  *reinterpret_cast<size_t *>(payload.data<uint8_t>() + payload_sz) = idx;
  return payload;
}

template <typename... Types>
void SerializableVariant<Types...>::Deserialize(yasl::ByteContainerView in) {
  YASL_ENFORCE(in.size() > sizeof(size_t), "Illegal buffer size {}", in.size());

  size_t idx =
      *reinterpret_cast<const size_t *>(in.data() + in.size() - sizeof(size_t));
  yasl::ByteContainerView payload(in.data(), in.size() - sizeof(size_t));

  var_ = schema2ns_vtable_[idx];
  visit([&](auto &clazz) { clazz.Deserialize(payload); });
}

template <typename... Types>
std::string SerializableVariant<Types...>::ToString() const {
  return visit([](auto &clazz) { return clazz.ToString(); });
}

template class SerializableVariant<HE_NAMESPACE_LIST(SecretKey)>;
template class SerializableVariant<HE_NAMESPACE_LIST(PublicKey)>;
template class SerializableVariant<HE_NAMESPACE_LIST(Ciphertext)>;

}  // namespace heu::lib::phe
