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

#include "heu/library/numpy/encryptor.h"

namespace heu::lib::numpy {

template <typename CLAZZ, typename PT>
using kHasVectorizedEncrypt = decltype(std::declval<const CLAZZ&>().Encrypt(
    absl::Span<const PT* const>()));

// PT is each algorithm's Plaintext
template <typename CLAZZ, typename PT>
auto DoCallEncrypt(const CLAZZ& sub_encryptor, const PMatrix& in, CMatrix* out)
    -> std::enable_if_t<
        std::experimental::is_detected_v<kHasVectorizedEncrypt, CLAZZ, PT>> {
  yasl::parallel_for(0, in.size(), 1, [&](int64_t beg, int64_t end) {
    std::vector<const PT*> pts;
    pts.reserve(end - beg);
    for (int64_t i = beg; i < end; ++i) {
      pts.push_back(&(in.data()[i].As<PT>()));
    }
    auto res = sub_encryptor.Encrypt(pts);
    for (int64_t i = beg; i < end; ++i) {
      out->data()[i] = phe::Ciphertext(std::move(res[i - beg]));
    }
  });
}

// PT is each algorithm's Plaintext
template <typename CLAZZ, typename PT>
auto DoCallEncrypt(const CLAZZ& sub_encryptor, const PMatrix& in, CMatrix* out)
    -> std::enable_if_t<
        !std::experimental::is_detected_v<kHasVectorizedEncrypt, CLAZZ, PT>> {
  yasl::parallel_for(0, in.size(), 1, [&](int64_t beg, int64_t end) {
    for (int64_t i = beg; i < end; ++i) {
      out->data()[i] =
          phe::Ciphertext(sub_encryptor.Encrypt(in.data()[i].As<PT>()));
    }
  });
}

CMatrix Encryptor::Encrypt(const PMatrix& in) const {
  CMatrix z(in.rows(), in.cols(), in.ndim());

#define FUNC(ns)                                                        \
  [&](const ns::Encryptor& sub_encryptor) {                             \
    DoCallEncrypt<ns::Encryptor, ns::Plaintext>(sub_encryptor, in, &z); \
  }

  std::visit(HE_DISPATCH(FUNC), encryptor_ptr_);
#undef FUNC

  return z;
}

template <typename CLAZZ, typename PT>
using kHasVectorizedEncryptWithAudit =
    decltype(std::declval<const CLAZZ&>().EncryptWithAudit(
        absl::Span<const PT* const>()));

// call vectorized EncryptWithAudit
template <typename CLAZZ, typename PT>
auto DoCallEncryptWithAudit(const CLAZZ& sub_encryptor, const PMatrix& in,
                            CMatrix* out_c, DenseMatrix<std::string>* out_s)
    -> std::enable_if_t<std::experimental::is_detected_v<
        kHasVectorizedEncryptWithAudit, CLAZZ, PT>> {
  yasl::parallel_for(0, in.size(), 1, [&](int64_t beg, int64_t end) {
    std::vector<const PT*> pts;
    pts.reserve(end - beg);
    for (int64_t i = beg; i < end; ++i) {
      pts.push_back(&(in.data()[i].As<PT>()));
    }
    auto res = sub_encryptor.EncryptWithAudit(pts);
    for (int64_t i = beg; i < end; ++i) {
      out_c->data()[i] = phe::Ciphertext(std::move(res.first[i - beg]));
      out_s->data()[i] = std::move(res.second[i - beg]);
    }
  });
}

// call scalar EncryptWithAudit
template <typename CLAZZ, typename PT>
auto DoCallEncryptWithAudit(const CLAZZ& sub_encryptor, const PMatrix& in,
                            CMatrix* out_c, DenseMatrix<std::string>* out_s)
    -> std::enable_if_t<!std::experimental::is_detected_v<
        kHasVectorizedEncryptWithAudit, CLAZZ, PT>> {
  yasl::parallel_for(0, in.size(), 1, [&](int64_t beg, int64_t end) {
    for (int64_t i = beg; i < end; ++i) {
      std::tie(out_c->data()[i], out_s->data()[i]) =
          sub_encryptor.EncryptWithAudit(in.data()[i].As<PT>());
    }
  });
}

std::pair<CMatrix, DenseMatrix<std::string>> Encryptor::EncryptWithAudit(
    const PMatrix& in) const {
  CMatrix z(in.rows(), in.cols(), in.ndim());
  DenseMatrix<std::string> adt(in.rows(), in.cols(), in.ndim());

#define FUNC(ns)                                                            \
  [&](const ns::Encryptor& sub_encryptor) {                                 \
    DoCallEncryptWithAudit<ns::Encryptor, ns::Plaintext>(sub_encryptor, in, \
                                                         &z, &adt);         \
  }

  std::visit(HE_DISPATCH(FUNC), encryptor_ptr_);
#undef FUNC
  return {z, adt};
}

}  // namespace heu::lib::numpy
