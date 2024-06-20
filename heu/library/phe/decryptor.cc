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

#include "heu/library/phe/decryptor.h"

#include "heu/library/phe/base/predefined_functions.h"

namespace heu::lib::phe {

template <typename CLAZZ, typename TYPE1, typename TYPE2>
using kHasScalarDecryptVoid = decltype(std::declval<const CLAZZ &>().Decrypt(
    std::declval<TYPE1>(), std::declval<TYPE2 *>()));

template <typename CLAZZ, typename TYPE1, typename TYPE2>
auto DoCallDecrypt(const CLAZZ &sub_clazz, const TYPE1 &in1, TYPE2 *out2)
    -> std::enable_if_t<std::experimental::is_detected_v<kHasScalarDecryptVoid,
                                                         CLAZZ, TYPE1, TYPE2>> {
  (sub_clazz.Decrypt(in1, out2));
}

template <typename CLAZZ, typename TYPE1, typename TYPE2>
auto DoCallDecrypt(const CLAZZ &sub_clazz, const TYPE1 &in1, TYPE2 *out2)
    -> std::enable_if_t<!std::experimental::is_detected_v<
        kHasScalarDecryptVoid, CLAZZ, TYPE1, TYPE2>> {
  (sub_clazz.Decrypt(absl::MakeConstSpan({&in1}), absl::MakeSpan(&out2, 1)));
}

void Decryptor::Decrypt(const Ciphertext &ct, Plaintext *out) const {
#define FUNC(ns)                                                    \
  [&](const ns::Decryptor &decryptor) {                             \
    if (!out->IsHoldType<ns::Plaintext>()) {                        \
      ns::Plaintext inner_pt;                                       \
      DoCallDecrypt(decryptor, ct.As<ns::Ciphertext>(), &inner_pt); \
      *out = std::move(inner_pt);                                   \
    } else {                                                        \
      DoCallDecrypt(decryptor, ct.As<ns::Ciphertext>(),             \
                    &out->As<ns::Plaintext>());                     \
    }                                                               \
  }

  std::visit(HE_DISPATCH(FUNC), decryptor_ptr_);
#undef FUNC
}

DEFINE_INVOKE_METHOD_RET_1(Plaintext, Decrypt);

Plaintext Decryptor::Decrypt(const Ciphertext &ct) const {
  return std::visit(
      HE_DISPATCH(DO_INVOKE_METHOD_RET_1, Decryptor, Decrypt, Ciphertext, ct),
      decryptor_ptr_);
}

Plaintext Decryptor::DecryptInRange(const Ciphertext &ct,
                                    size_t range_bits) const {
  auto pt = Decrypt(ct);
  YACL_ENFORCE(
      pt.BitCount() <= range_bits,
      "Dangerous!!! HE ciphertext range check failed, there may be a malicious "
      "party stealing your data, please stop computing immediately. "
      "pt.BitCount()={}, expected {}",
      pt.BitCount(), range_bits);
  return pt;
}

SchemaType Decryptor::GetSchemaType() const { return schema_type_; }

}  // namespace heu::lib::phe
