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

CMatrix Encryptor::Encrypt(const DenseMatrix<phe::Plaintext>& in) const {
  CMatrix z(in.rows(), in.cols(), in.ndim());
  in.ForEach([&](int64_t row, int64_t col, const phe::Plaintext& pt) {
    z(row, col) = phe::Encryptor::Encrypt(pt);
  });
  return z;
}

std::pair<CMatrix, DenseMatrix<std::string>> Encryptor::EncryptWithAudit(
    const PMatrix& in) const {
  CMatrix z(in.rows(), in.cols(), in.ndim());
  DenseMatrix<std::string> adt(in.rows(), in.cols(), in.ndim());
  in.ForEach([&](int64_t row, int64_t col, const phe::Plaintext& pt) {
    std::tie(z(row, col), adt(row, col)) = phe::Encryptor::EncryptWithAudit(pt);
  });
  return {z, adt};
}

}  // namespace heu::lib::numpy
