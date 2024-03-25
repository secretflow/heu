// Copyright 2024 Ant Group Co., Ltd.
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

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "heu/spi/auto_test/tool.h"
#include "heu/spi/he/he.h"

namespace heu::spi::test {

class CkksTest : public testing::TestWithParam<std::shared_ptr<HeKit>> {
  void SetUp() override {
    kit_ = GetParam();
    fmt::println("Testing {}", *kit_);

    itool_ = kit_->GetItemTool();
    enc_ = kit_->GetEncryptor();
    eval_ = kit_->GetWordEvaluator();
    dec_ = kit_->GetDecryptor();
  }

 protected:
  std::shared_ptr<HeKit> kit_;

  std::shared_ptr<ItemTool> itool_;
  std::shared_ptr<Encryptor> enc_;
  std::shared_ptr<WordEvaluator> eval_;
  std::shared_ptr<Decryptor> dec_;
};

INSTANTIATE_TEST_SUITE_P(HeCollection, CkksTest,
                         SelectHeKitsForTest({FeatureSet::ApproxFHE}),
                         GenTestName<CkksTest>);

TEST_P(CkksTest, TestEvaluate) {
  using namespace std::complex_literals;
  auto edr = kit_->GetEncoder(ArgEncodingMethod = "batch");

  std::vector<std::complex<double>> pts1_vec = {
      0, 1, -1, 1i, -2i, 3. + 4i, 8.5 - 8i, -2.5 + .1i, -1.4 + .1i};
  const auto pts1 = edr->Encode(pts1_vec);
  const auto cts1 = enc_->Encrypt(pts1);
  const std::vector<std::complex<double>> pts2_vec = {
      -1i, 1i, 2.1 - 5i, 2.9 + .9i, 3, 0.5, -1.1 + 1i, 2. + 2i, 3. + 3i};
  const auto pts2 = edr->Encode(pts2_vec);
  const auto cts2 = enc_->Encrypt(pts2);

  // test equal
  EXPECT_TRUE(itool_->Equal(pts1, pts1));
  EXPECT_FALSE(itool_->Equal(pts1, pts2));
  EXPECT_FALSE(itool_->Equal(pts1, cts1));
  EXPECT_FALSE(itool_->Equal(cts1, cts2));
  EXPECT_TRUE(itool_->Equal(cts2, cts2));
  EXPECT_TRUE(itool_->Equal(pts1, edr->Encode(pts1_vec)));

  // negate
  Item res = eval_->Negate(pts1);
  EXPECT_THAT(
      edr->DecodeComplex(res),
      BeginWith<std::vector<std::complex<double>>>(
          {0, -1, 1, -1i, 2i, -3. - 4i, -8.5 + 8i, 2.5 - 0.1i, 1.4 - 0.1i}));
  res = eval_->Negate(cts1);
  EXPECT_THAT(
      edr->DecodeComplex(dec_->Decrypt(res)),
      BeginWith<std::vector<std::complex<double>>>(
          {0, -1, 1, -1i, 2i, -3. - 4i, -8.5 + 8i, 2.5 - 0.1i, 1.4 - 0.1i}));

  // add
  res = eval_->Add(cts1, cts2);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {-1i, 1. + 1i, 1.1 - 5i, 2.9 + 1.9i, 3. - 2i, 3.5 + 4i,
                   7.4 - 7i, -0.5 + 2.1i, 1.6 + 3.1i}));
  res = eval_->Add(cts1, pts2);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {-1i, 1. + 1i, 1.1 - 5i, 2.9 + 1.9i, 3. - 2i, 3.5 + 4i,
                   7.4 - 7i, -0.5 + 2.1i, 1.6 + 3.1i}));
  res = eval_->Add(pts1, cts2);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {-1i, 1. + 1i, 1.1 - 5i, 2.9 + 1.9i, 3. - 2i, 3.5 + 4i,
                   7.4 - 7i, -0.5 + 2.1i, 1.6 + 3.1i}));
  res = eval_->Add(pts1, pts2);
  EXPECT_THAT(edr->DecodeComplex(res),
              BeginWith<std::vector<std::complex<double>>>(
                  {-1i, 1. + 1i, 1.1 - 5i, 2.9 + 1.9i, 3. - 2i, 3.5 + 4i,
                   7.4 - 7i, -0.5 + 2.1i, 1.6 + 3.1i}));

  // sub
  res = eval_->Sub(cts1, cts2);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {1i, 1. - 1i, -3.1 + 5i, -2.9 + 0.1i, -3. - 2i, 2.5 + 4i,
                   9.6 - 9i, -4.5 - 1.9i, -4.4 - 2.9i}));
  res = eval_->Sub(cts1, pts2);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {1i, 1. - 1i, -3.1 + 5i, -2.9 + 0.1i, -3. - 2i, 2.5 + 4i,
                   9.6 - 9i, -4.5 - 1.9i, -4.4 - 2.9i}));
  res = eval_->Sub(pts1, cts2);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {1i, 1. - 1i, -3.1 + 5i, -2.9 + 0.1i, -3. - 2i, 2.5 + 4i,
                   9.6 - 9i, -4.5 - 1.9i, -4.4 - 2.9i}));
  res = eval_->Sub(pts1, pts2);
  EXPECT_THAT(edr->DecodeComplex(res),
              BeginWith<std::vector<std::complex<double>>>(
                  {1i, 1. - 1i, -3.1 + 5i, -2.9 + 0.1i, -3. - 2i, 2.5 + 4i,
                   9.6 - 9i, -4.5 - 1.9i, -4.4 - 2.9i}));

  // mul
  res = eval_->Mul(cts1, pts2);
  res = eval_->Relinearize(res);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {0, 1i, -2.1 + 5i, -0.9 + 2.9i, -6i, 1.5 + 2i, -1.35 + 17.3i,
                   -5.2 - 4.8i, -4.5 - 3.9i}));
  res = eval_->Mul(pts1, cts2);
  res = eval_->Relinearize(res);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {0, 1i, -2.1 + 5i, -0.9 + 2.9i, -6i, 1.5 + 2i, -1.35 + 17.3i,
                   -5.2 - 4.8i, -4.5 - 3.9i}));
  res = eval_->Mul(pts1, pts2);
  EXPECT_THAT(edr->DecodeComplex(res),
              BeginWith<std::vector<std::complex<double>>>(
                  {0, 1i, -2.1 + 5i, -0.9 + 2.9i, -6i, 1.5 + 2i, -1.35 + 17.3i,
                   -5.2 - 4.8i, -4.5 - 3.9i}));
  res = eval_->Mul(cts1, cts2);
  res = eval_->Relinearize(res);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {0, 1i, -2.1 + 5i, -0.9 + 2.9i, -6i, 1.5 + 2i, -1.35 + 17.3i,
                   -5.2 - 4.8i, -4.5 - 3.9i}));

  // square
  res = eval_->Square(cts2);
  EXPECT_THAT(
      edr->DecodeComplex(dec_->Decrypt(res)),
      BeginWith<std::vector<std::complex<double>>>(
          {-1, -1, -20.59 - 21i, 7.6 + 5.22i, 9, 0.25, 0.21 - 2.2i, 8i, 18i}));
  res = eval_->Square(pts2);
  EXPECT_THAT(
      edr->DecodeComplex(res),
      BeginWith<std::vector<std::complex<double>>>(
          {-1, -1, -20.59 - 21i, 7.6 + 5.22i, 9, 0.25, 0.21 - 2.2i, 8i, 18i}));

  // pow pts
  res = eval_->Pow(pts2, 1);
  EXPECT_THAT(
      edr->DecodeComplex(res),
      BeginWith<std::vector<std::complex<double>>>(
          {-1i, 1i, 2.1 - 5i, 2.9 + .9i, 3, 0.5, -1.1 + 1i, 2. + 2i, 3. + 3i}));
  res = eval_->Pow(pts2, 3);
  EXPECT_THAT(edr->DecodeComplex(res),
              BeginWith<std::vector<std::complex<double>>>(
                  {1i, -1i, -148.239 + 58.85i, 17.342 + 21.978i, 27, 0.125,
                   1.969 + 2.63i, -16. + 16i, -54. + 54i}));

  // pow cts
  res = eval_->Pow(cts2, 1);
  EXPECT_THAT(
      edr->DecodeComplex(dec_->Decrypt(res)),
      BeginWith<std::vector<std::complex<double>>>(
          {-1i, 1i, 2.1 - 5i, 2.9 + .9i, 3, 0.5, -1.1 + 1i, 2. + 2i, 3. + 3i}));
  res = eval_->Pow(cts2, 3);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {1i, -1i, -148.239 + 58.85i, 17.342 + 21.978i, 27, 0.125,
                   1.969 + 2.63i, -16. + 16i, -54. + 54i}));

  // conjugate
  res = eval_->Conjugate(cts1);
  EXPECT_THAT(
      edr->DecodeComplex(dec_->Decrypt(res)),
      BeginWith<std::vector<std::complex<double>>>(
          {0, 1, -1, -1i, 2i, 3. - 4i, 8.5 + 8i, -2.5 - 0.1i, -1.4 - 0.1i}));

  // rotate
  res = eval_->Rotate(cts2, -1);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(res)),
              BeginWith<std::vector<std::complex<double>>>(
                  {0, -1i, 1i, 2.1 - 5i, 2.9 + .9i, 3, 0.5, -1.1 + 1i, 2. + 2i,
                   3. + 3i}));
  res = eval_->Rotate(cts2, 1);
  auto res_vec = edr->DecodeComplex(dec_->Decrypt(res));
  EXPECT_THAT(res_vec, BeginWith<std::vector<std::complex<double>>>(
                           {1i, 2.1 - 5i, 2.9 + .9i, 3, 0.5, -1.1 + 1i, 2. + 2i,
                            3. + 3i}));
  EXPECT_EQ(res_vec[res_vec.size() - 1], -1i);
}

TEST_P(CkksTest, TestEvaluateInplace) {
  using namespace std::complex_literals;
  auto edr = kit_->GetEncoder(ArgEncodingMethod = "batch");

  const std::vector<std::complex<double>> pts1_vec = {
      0, 1, -1, 1i, -2i, 3. + 4i, 8.5 - 8i, -2.5 + .1i, -1.4 + .1i};
  const std::vector<std::complex<double>> pts2_vec = {
      -1i, 1i, 2.1 - 5i, 2.9 + .9i, 3, 0.5, -1.1 + 1i, 2. + 2i, 3. + 3i};
  const auto pts2 = edr->Encode(pts2_vec);
  const auto cts2 = enc_->Encrypt(pts2);

  // negate
  auto pts1 = edr->Encode(pts1_vec);
  auto cts1 = enc_->Encrypt(pts1);
  eval_->NegateInplace(&pts1);
  EXPECT_THAT(
      edr->DecodeComplex(pts1),
      BeginWith<std::vector<std::complex<double>>>(
          {0, -1, 1, -1i, 2i, -3. - 4i, -8.5 + 8i, 2.5 - 0.1i, 1.4 - 0.1i}));
  eval_->NegateInplace(&cts1);
  EXPECT_THAT(
      edr->DecodeComplex(dec_->Decrypt(cts1)),
      BeginWith<std::vector<std::complex<double>>>(
          {0, -1, 1, -1i, 2i, -3. - 4i, -8.5 + 8i, 2.5 - 0.1i, 1.4 - 0.1i}));

  // add
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->AddInplace(&cts1, cts2);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(cts1)),
              BeginWith<std::vector<std::complex<double>>>(
                  {-1i, 1. + 1i, 1.1 - 5i, 2.9 + 1.9i, 3. - 2i, 3.5 + 4i,
                   7.4 - 7i, -0.5 + 2.1i, 1.6 + 3.1i}));

  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->AddInplace(&cts1, pts2);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(cts1)),
              BeginWith<std::vector<std::complex<double>>>(
                  {-1i, 1. + 1i, 1.1 - 5i, 2.9 + 1.9i, 3. - 2i, 3.5 + 4i,
                   7.4 - 7i, -0.5 + 2.1i, 1.6 + 3.1i}));

  // sub
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->SubInplace(&cts1, cts2);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(cts1)),
              BeginWith<std::vector<std::complex<double>>>(
                  {1i, 1. - 1i, -3.1 + 5i, -2.9 + 0.1i, -3. - 2i, 2.5 + 4i,
                   9.6 - 9i, -4.5 - 1.9i, -4.4 - 2.9i}));

  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->SubInplace(&cts1, pts2);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(cts1)),
              BeginWith<std::vector<std::complex<double>>>(
                  {1i, 1. - 1i, -3.1 + 5i, -2.9 + 0.1i, -3. - 2i, 2.5 + 4i,
                   9.6 - 9i, -4.5 - 1.9i, -4.4 - 2.9i}));

  // mul
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->MulInplace(&cts1, pts2);
  eval_->RelinearizeInplace(&cts1);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(cts1)),
              BeginWith<std::vector<std::complex<double>>>(
                  {0, 1i, -2.1 + 5i, -0.9 + 2.9i, -6i, 1.5 + 2i, -1.35 + 17.3i,
                   -5.2 - 4.8i, -4.5 - 3.9i}));
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->MulInplace(&cts1, cts2);
  eval_->RelinearizeInplace(&cts1);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(cts1)),
              BeginWith<std::vector<std::complex<double>>>(
                  {0, 1i, -2.1 + 5i, -0.9 + 2.9i, -6i, 1.5 + 2i, -1.35 + 17.3i,
                   -5.2 - 4.8i, -4.5 - 3.9i}));

  // square
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->SquareInplace(&cts1);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(cts1)),
              BeginWith<std::vector<std::complex<double>>>(
                  {0, 1, 1, -1, -4, -7. + 24i, 8.25 - 136i, 6.24 - 0.5i,
                   1.95 - 0.28i}));
  pts1 = edr->Encode(pts1_vec);
  eval_->SquareInplace(&pts1);
  EXPECT_THAT(edr->DecodeComplex(pts1),
              BeginWith<std::vector<std::complex<double>>>(
                  {0, 1, 1, -1, -4, -7. + 24i, 8.25 - 136i, 6.24 - 0.5i,
                   1.95 - 0.28i}));

  // pow pts
  auto pts_exp = edr->Encode(pts2_vec);
  eval_->PowInplace(&pts_exp, 1);
  EXPECT_THAT(
      edr->DecodeComplex(pts_exp),
      BeginWith<std::vector<std::complex<double>>>(
          {-1i, 1i, 2.1 - 5i, 2.9 + .9i, 3, 0.5, -1.1 + 1i, 2. + 2i, 3. + 3i}));
  pts_exp = edr->Encode(pts2_vec);
  eval_->PowInplace(&pts_exp, 4);
  EXPECT_THAT(edr->DecodeComplex(pts_exp),
              BeginWith<std::vector<std::complex<double>>>(
                  {1, 1, -17.0519 + 864.78i, 30.5116 + 79.344i, 81, 0.0625,
                   -4.7959 - 0.9240i, -64, -324}));

  // pow cts
  auto cts_exp = enc_->Encrypt(edr->Encode(pts2_vec));
  eval_->PowInplace(&cts_exp, 1);
  EXPECT_THAT(
      edr->DecodeComplex(dec_->Decrypt(cts_exp)),
      BeginWith<std::vector<std::complex<double>>>(
          {-1i, 1i, 2.1 - 5i, 2.9 + .9i, 3, 0.5, -1.1 + 1i, 2. + 2i, 3. + 3i}));
  eval_->PowInplace(&cts_exp, 4);
  EXPECT_THAT(edr->DecodeComplex(dec_->Decrypt(cts_exp)),
              BeginWith<std::vector<std::complex<double>>>(
                  {1, 1, -17.0519 + 864.78i, 30.5116 + 79.344i, 81, 0.0625,
                   -4.7959 - 0.9240i, -64, -324}));

  // ct randomize
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->Randomize(&cts1);
  EXPECT_THAT(
      edr->DecodeComplex(dec_->Decrypt(cts1)),
      BeginWith<std::vector<std::complex<double>>>(
          {0, 1, -1, 1i, -2i, 3. + 4i, 8.5 - 8i, -2.5 + .1i, -1.4 + .1i}));

  // rotate inplace
  cts1 = enc_->Encrypt(edr->Encode(pts1_vec));
  eval_->RotateInplace(&cts1, 2);
  auto res = edr->DecodeComplex(dec_->Decrypt(cts1));
  EXPECT_THAT(res,
              BeginWith<std::vector<std::complex<double>>>(
                  {-1, 1i, -2i, 3. + 4i, 8.5 - 8i, -2.5 + .1i, -1.4 + .1i}));
  EXPECT_EQ(res[res.size() - 2], 0.);
  EXPECT_EQ(res[res.size() - 1], 1.);
}

TEST_P(CkksTest, TestEncodingSingle) {
  auto edr = kit_->GetEncoder(ArgEncodingMethod = "batch");

  auto pt1 = edr->Encode((int64_t)-443);
  EXPECT_THAT(edr->DecodeInt64(pt1), BeginWith<std::vector<int64_t>>({-443}));
  pt1 = edr->Encode((uint64_t)443);
  EXPECT_THAT(edr->DecodeUint64(pt1), BeginWith<std::vector<uint64_t>>({443}));
  pt1 = edr->Encode(5.5);
  EXPECT_THAT(edr->DecodeDouble(pt1), BeginWith<std::vector<double>>({5.5}));

  using namespace std::complex_literals;
  pt1 = edr->Encode(1.9 - 5.5i);
  EXPECT_THAT(edr->DecodeComplex(pt1),
              BeginWith<std::vector<std::complex<double>>>({1.9 - 5.5i}));
}

}  // namespace heu::spi::test
