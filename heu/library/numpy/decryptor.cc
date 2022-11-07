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

#include "heu/library/numpy/decryptor.h"

namespace heu::lib::numpy {

template <typename CLAZZ, typename CT>
using kHasVectorizedDecrypt = decltype(std::declval<const CLAZZ&>().Decrypt(
    absl::Span<const CT* const>()));

// CT is each algorithm's Ciphertext
template <typename CLAZZ, typename CT>
auto DoCallDecrypt(const CLAZZ& sub_decryptor, const CMatrix& in, PMatrix* out)
    -> std::enable_if_t<
        std::experimental::is_detected_v<kHasVectorizedDecrypt, CLAZZ, CT>> {
  yasl::parallel_for(0, in.size(), 1, [&](int64_t beg, int64_t end) {
    std::vector<const CT*> cts;
    cts.reserve(end - beg);
    for (int64_t i = beg; i < end; ++i) {
      cts.push_back(&(in.data()[i].As<CT>()));
    }
    auto res = sub_decryptor.Decrypt(cts);
    for (int64_t i = beg; i < end; ++i) {
      out->data()[i] = std::move(res[i - beg]);
    }
  });
}

// CT is each algorithm's Ciphertext
template <typename CLAZZ, typename CT>
auto DoCallDecrypt(const CLAZZ& sub_decryptor, const CMatrix& in, PMatrix* out)
    -> std::enable_if_t<
        !std::experimental::is_detected_v<kHasVectorizedDecrypt, CLAZZ, CT>> {
  yasl::parallel_for(0, in.size(), 1, [&](int64_t beg, int64_t end) {
    for (int64_t i = beg; i < end; ++i) {
      out->data()[i] = sub_decryptor.Decrypt(in.data()[i].As<CT>());
    }
  });
}

PMatrix Decryptor::Decrypt(const CMatrix& in) const {
  PMatrix out(in.rows(), in.cols(), in.ndim());

#define FUNC(ns)                                                           \
  [&](const ns::Decryptor& sub_decryptor) {                                \
    DoCallDecrypt<ns::Decryptor, ns::Ciphertext>(sub_decryptor, in, &out); \
  }

  std::visit(HE_DISPATCH(FUNC), decryptor_ptr_);
#undef FUNC

  return out;
}

}  // namespace heu::lib::numpy
