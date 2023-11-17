// Copyright 2023 Ant Group Co., Ltd.
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

#include "gtest/gtest.h"

#include "heu/library/numpy/test/test_tools.h"

namespace heu::lib::numpy::test {

TEST(IcTest, CtSerializeIcWorks) {
  auto he_kit = HeKit(phe::HeKit(phe::SchemaType::IcPaillier, 2048));

  // test pt matrix
  auto pts1 = GenMatrix(he_kit.GetSchemaType(), 100, 300);
  auto buf = pts1.Serialize(MatrixSerializeFormat::Interconnection);
  ASSERT_GT(buf.size(), 0);
  DenseMatrix<phe::Plaintext> pts2 = DenseMatrix<phe::Plaintext>::LoadFrom(
      buf, MatrixSerializeFormat::Interconnection);
  AssertMatrixEq(pts1, pts2);

  // test ct matrix
  auto cts1 = he_kit.GetEncryptor()->Encrypt(pts1);
  buf = cts1.Serialize(MatrixSerializeFormat::Interconnection);
  std::string str = std::string(buf.data<char>(), buf.size());
  auto cts2 = DenseMatrix<phe::Ciphertext>::LoadFrom(
      str, MatrixSerializeFormat::Interconnection);
  AssertMatrixEq(cts1, cts2);

  auto pts3 = he_kit.GetDecryptor()->Decrypt(cts2);
  AssertMatrixEq(pts1, pts3);
}

}  // namespace heu::lib::numpy::test
