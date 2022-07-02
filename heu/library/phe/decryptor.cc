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

namespace heu::lib::phe {

#define HE_SPECIAL_T1_MPINT_VOID(ns, clazz, func, type1, in1, mpint_var) \
  [&](const ns::clazz& eval) { eval.func(in1.get<ns::type1>(), mpint_var); }

void Decryptor::Decrypt(const Ciphertext& ct, Plaintext* out) const {
  std::visit(HE_DISPATCH(HE_SPECIAL_T1_MPINT_VOID, Decryptor, Decrypt,
                         Ciphertext, ct, out),
             decryptor_ptr_);
}

Plaintext Decryptor::Decrypt(const Ciphertext& ct) const {
  return std::visit(HE_DISPATCH(HE_METHOD_T1_RET, Decryptor, Plaintext, Decrypt,
                                Ciphertext, ct),
                    decryptor_ptr_);
}

}  // namespace heu::lib::phe
