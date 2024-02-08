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

#include <memory>

#include "gtest/gtest.h"

#include "heu/spi/he/sketches/scalar/test/dummy_ops.h"

namespace heu::lib::spi::test {

class TestWessScalarCall : public ::testing::Test {
 protected:
  std::unique_ptr<WordEvaluator> we_ = std::make_unique<DummyEvaluatorImpl>();
};

TEST_F(TestWessScalarCall, TestScalar) {
  Item pt = {DummyPt("1"), ContentType::Plaintext};
  EXPECT_TRUE(pt.IsPlaintext());
  Item ct(DummyCt("1"), ContentType::Ciphertext);
  EXPECT_TRUE(ct.IsCiphertext());

  // negate
  Item res = we_->Negate(pt);
  EXPECT_TRUE(res.IsPlaintext());
  EXPECT_EQ(res.As<DummyPt>().Id(), "-pt1");
  res = we_->Negate(ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "-ct1");

  // add
  res = we_->Add(ct, ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "ct1+ct1");
  res = we_->Add(ct, pt);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "ct1+pt1");
  res = we_->Add(pt, ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "pt1+ct1");
  res = we_->Add(pt, pt);
  EXPECT_TRUE(res.IsPlaintext());
  EXPECT_EQ(res.As<DummyPt>().Id(), "pt1+pt1");

  // sub
  res = we_->Sub(ct, ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "ct1-ct1");
  res = we_->Sub(ct, pt);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "ct1-pt1");
  res = we_->Sub(pt, ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "pt1-ct1");
  res = we_->Sub(pt, pt);
  EXPECT_TRUE(res.IsPlaintext());
  EXPECT_EQ(res.As<DummyPt>().Id(), "pt1-pt1");

  // mul
  res = we_->Mul(ct, ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "ct1*ct1");
  res = we_->Mul(ct, pt);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "ct1*pt1");
  res = we_->Mul(pt, ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "pt1*ct1");
  res = we_->Mul(pt, pt);
  EXPECT_TRUE(res.IsPlaintext());
  EXPECT_EQ(res.As<DummyPt>().Id(), "pt1*pt1");

  // square
  res = we_->Square(pt);
  EXPECT_TRUE(res.IsPlaintext());
  EXPECT_EQ(res.As<DummyPt>().Id(), "(pt1)^2");
  res = we_->Square(ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "(ct1)^2");

  // exp
  res = we_->Pow(pt, 12345);
  EXPECT_TRUE(res.IsPlaintext());
  EXPECT_EQ(res.As<DummyPt>().Id(), "(pt1)^12345");
  res = we_->Pow(ct, -12345);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "(ct1)^-12345");

  // ct maintain
  res = we_->Relinearize(ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "rl(ct1)");

  res = we_->ModSwitch(ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "ms(ct1)");

  res = we_->Rescale(ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "rs(ct1)");

  // automorphism
  res = we_->SwapRows(ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "sr(ct1)");

  res = we_->Conjugate(ct);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "cj(ct1)");

  res = we_->Rotate(ct, 0);
  EXPECT_TRUE(res.IsCiphertext());
  EXPECT_EQ(res.As<DummyCt>().Id(), "ct1<<0");
}

TEST_F(TestWessScalarCall, TestScalarInplace) {
  // negate
  Item pt = {DummyPt("2"), ContentType::Plaintext};
  Item ct(DummyCt("2"), ContentType::Ciphertext);
  we_->NegateInplace(&pt);
  EXPECT_TRUE(pt.IsPlaintext());
  EXPECT_EQ(pt.As<DummyPt>().Id(), ":= -pt2");
  we_->NegateInplace(&ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), ":= -ct2");

  // add
  pt = {DummyPt("2"), ContentType::Plaintext};
  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->AddInplace(&ct, ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "ct2+=ct2");
  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->AddInplace(&ct, pt);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "ct2+=pt2");

  // sub
  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->SubInplace(&ct, ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "ct2-=ct2");
  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->SubInplace(&ct, pt);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "ct2-=pt2");

  // mul
  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->MulInplace(&ct, ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "ct2*=ct2");
  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->MulInplace(&ct, pt);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "ct2*=pt2");

  // square
  pt = {DummyPt("2"), ContentType::Plaintext};
  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->SquareInplace(&pt);
  EXPECT_TRUE(pt.IsPlaintext());
  EXPECT_EQ(pt.As<DummyPt>().Id(), ":= (pt2)^2");
  we_->SquareInplace(&ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), ":= (ct2)^2");

  // pow
  pt = {DummyPt("2"), ContentType::Plaintext};
  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->PowInplace(&pt, 0);
  EXPECT_TRUE(pt.IsPlaintext());
  EXPECT_EQ(pt.As<DummyPt>().Id(), ":= (pt2)^0");
  we_->PowInplace(&ct, 1);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), ":= (ct2)^1");

  // ct maintain
  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->Randomize(&ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), ":= rand(ct2)");

  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->RelinearizeInplace(&ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), ":= rl(ct2)");

  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->ModSwitchInplace(&ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), ":= ms(ct2)");

  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->RescaleInplace(&ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), ":= rs(ct2)");

  // automorphism
  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->SwapRowsInplace(&ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), ":= sr(ct2)");

  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->ConjugateInplace(&ct);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), ":= cj(ct2)");

  ct = {DummyCt("2"), ContentType::Ciphertext};
  we_->RotateInplace(&ct, -12);
  EXPECT_TRUE(ct.IsCiphertext());
  EXPECT_EQ(ct.As<DummyCt>().Id(), "ct2<<=-12");
}

}  // namespace heu::lib::spi::test
