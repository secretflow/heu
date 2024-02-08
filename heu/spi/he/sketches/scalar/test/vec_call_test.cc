// Copyright 2024 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License"});
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
#include <string>
#include <utility>
#include <vector>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "heu/spi/he/sketches/scalar/test/dummy_ops.h"

namespace heu::lib::spi::test {

class TestWessVecCall : public ::testing::Test {
 protected:
  std::unique_ptr<WordEvaluator> we_ = std::make_unique<DummyEvaluatorImpl>();
};

TEST_F(TestWessVecCall, TestVec) {
  std::vector<DummyPt> pts_vec = {DummyPt("1"), DummyPt("2"), DummyPt("3")};
  auto pts = Item::Take(std::move(pts_vec), ContentType::Plaintext);

  std::vector<DummyCt> cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  auto cts = Item::Ref(cts_vec, ContentType::Ciphertext);

  // negate
  Item res = we_->Negate(pts);
  ExpectItemEq<DummyPt>(res, {"-pt1", "-pt2", "-pt3"});
  res = we_->Negate(cts);
  ExpectItemEq<DummyCt>(res, {"-ct1", "-ct2", "-ct3"});

  // add
  res = we_->Add(cts, cts);
  ExpectItemEq<DummyCt>(res, {"ct1+ct1", "ct2+ct2", "ct3+ct3"});
  res = we_->Add(cts, pts);
  ExpectItemEq<DummyCt>(res, {"ct1+pt1", "ct2+pt2", "ct3+pt3"});
  res = we_->Add(pts, cts);
  ExpectItemEq<DummyCt>(res, {"pt1+ct1", "pt2+ct2", "pt3+ct3"});
  res = we_->Add(pts, pts);
  ExpectItemEq<DummyPt>(res, {"pt1+pt1", "pt2+pt2", "pt3+pt3"});

  // sub
  res = we_->Sub(cts, cts);
  ExpectItemEq<DummyCt>(res, {"ct1-ct1", "ct2-ct2", "ct3-ct3"});
  res = we_->Sub(cts, pts);
  ExpectItemEq<DummyCt>(res, {"ct1-pt1", "ct2-pt2", "ct3-pt3"});
  res = we_->Sub(pts, cts);
  ExpectItemEq<DummyCt>(res, {"pt1-ct1", "pt2-ct2", "pt3-ct3"});
  res = we_->Sub(pts, pts);
  ExpectItemEq<DummyPt>(res, {"pt1-pt1", "pt2-pt2", "pt3-pt3"});

  // mul
  res = we_->Mul(cts, cts);
  ExpectItemEq<DummyCt>(res, {"ct1*ct1", "ct2*ct2", "ct3*ct3"});
  res = we_->Mul(cts, pts);
  ExpectItemEq<DummyCt>(res, {"ct1*pt1", "ct2*pt2", "ct3*pt3"});
  res = we_->Mul(pts, cts);
  ExpectItemEq<DummyCt>(res, {"pt1*ct1", "pt2*ct2", "pt3*ct3"});
  res = we_->Mul(pts, pts);
  ExpectItemEq<DummyPt>(res, {"pt1*pt1", "pt2*pt2", "pt3*pt3"});

  // square
  res = we_->Square(pts);
  ExpectItemEq<DummyPt>(res, {"(pt1)^2", "(pt2)^2", "(pt3)^2"});
  res = we_->Square(cts);
  ExpectItemEq<DummyCt>(res, {"(ct1)^2", "(ct2)^2", "(ct3)^2"});

  // exp
  res = we_->Pow(pts, 12);
  ExpectItemEq<DummyPt>(res, {"(pt1)^12", "(pt2)^12", "(pt3)^12"});
  res = we_->Pow(cts, -12);
  ExpectItemEq<DummyCt>(res, {"(ct1)^-12", "(ct2)^-12", "(ct3)^-12"});

  // ct maintain
  res = we_->Relinearize(cts);
  ExpectItemEq<DummyCt>(res, {"rl(ct1)", "rl(ct2)", "rl(ct3)"});
  res = we_->ModSwitch(cts);
  ExpectItemEq<DummyCt>(res, {"ms(ct1)", "ms(ct2)", "ms(ct3)"});
  res = we_->Rescale(cts);
  ExpectItemEq<DummyCt>(res, {"rs(ct1)", "rs(ct2)", "rs(ct3)"});

  // automorphism
  res = we_->SwapRows(cts);
  ExpectItemEq<DummyCt>(res, {"sr(ct1)", "sr(ct2)", "sr(ct3)"});
  res = we_->Conjugate(cts);
  ExpectItemEq<DummyCt>(res, {"cj(ct1)", "cj(ct2)", "cj(ct3)"});
  res = we_->Rotate(cts, -1);
  ExpectItemEq<DummyCt>(res, {"ct1<<-1", "ct2<<-1", "ct3<<-1"});
}

TEST_F(TestWessVecCall, TestVecInplace) {
  std::vector<DummyPt> pts_vec = {DummyPt("1"), DummyPt("2"), DummyPt("3")};
  auto pts = Item::Ref(pts_vec, ContentType::Plaintext);
  std::vector<DummyCt> cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  auto cts = Item::Ref(cts_vec, ContentType::Ciphertext);

  // negate
  we_->NegateInplace(&pts);
  ExpectItemEq<DummyPt>(pts, {":= -pt1", ":= -pt2", ":= -pt3"});
  we_->NegateInplace(&cts);
  ExpectItemEq<DummyCt>(cts, {":= -ct1", ":= -ct2", ":= -ct3"});

  // add
  pts_vec = {DummyPt("1"), DummyPt("2"), DummyPt("3")};
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->AddInplace(&cts, cts);
  ExpectItemEq<DummyCt>(cts, {"ct1+=ct1", "ct2+=ct2", "ct3+=ct3"});
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->AddInplace(&cts, pts);
  ExpectItemEq<DummyCt>(cts, {"ct1+=pt1", "ct2+=pt2", "ct3+=pt3"});

  // sub
  pts_vec = {DummyPt("1"), DummyPt("2"), DummyPt("3")};
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->SubInplace(&cts, cts);
  ExpectItemEq<DummyCt>(cts, {"ct1-=ct1", "ct2-=ct2", "ct3-=ct3"});
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->SubInplace(&cts, pts);
  ExpectItemEq<DummyCt>(cts, {"ct1-=pt1", "ct2-=pt2", "ct3-=pt3"});

  // mul
  pts_vec = {DummyPt("1"), DummyPt("2"), DummyPt("3")};
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->MulInplace(&cts, cts);
  ExpectItemEq<DummyCt>(cts, {"ct1*=ct1", "ct2*=ct2", "ct3*=ct3"});
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->MulInplace(&cts, pts);
  ExpectItemEq<DummyCt>(cts, {"ct1*=pt1", "ct2*=pt2", "ct3*=pt3"});

  // square
  pts_vec = {DummyPt("1"), DummyPt("2"), DummyPt("3")};
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->SquareInplace(&pts);
  ExpectItemEq<DummyPt>(pts, {":= (pt1)^2", ":= (pt2)^2", ":= (pt3)^2"});
  we_->SquareInplace(&cts);
  ExpectItemEq<DummyCt>(cts, {":= (ct1)^2", ":= (ct2)^2", ":= (ct3)^2"});

  // pow
  pts_vec = {DummyPt("1"), DummyPt("2"), DummyPt("3")};
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->PowInplace(&pts, 0);
  ExpectItemEq<DummyPt>(pts, {":= (pt1)^0", ":= (pt2)^0", ":= (pt3)^0"});
  we_->PowInplace(&cts, 1);
  ExpectItemEq<DummyCt>(cts, {":= (ct1)^1", ":= (ct2)^1", ":= (ct3)^1"});

  // ct maintain
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->Randomize(&cts);
  ExpectItemEq<DummyCt>(cts, {":= rand(ct1)", ":= rand(ct2)", ":= rand(ct3)"});
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->RelinearizeInplace(&cts);
  ExpectItemEq<DummyCt>(cts, {":= rl(ct1)", ":= rl(ct2)", ":= rl(ct3)"});
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->ModSwitchInplace(&cts);
  ExpectItemEq<DummyCt>(cts, {":= ms(ct1)", ":= ms(ct2)", ":= ms(ct3)"});
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->RescaleInplace(&cts);
  ExpectItemEq<DummyCt>(cts, {":= rs(ct1)", ":= rs(ct2)", ":= rs(ct3)"});

  // automorphism
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->SwapRowsInplace(&cts);
  ExpectItemEq<DummyCt>(cts, {":= sr(ct1)", ":= sr(ct2)", ":= sr(ct3)"});
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->ConjugateInplace(&cts);
  ExpectItemEq<DummyCt>(cts, {":= cj(ct1)", ":= cj(ct2)", ":= cj(ct3)"});
  cts_vec = {DummyCt("1"), DummyCt("2"), DummyCt("3")};
  we_->RotateInplace(&cts, -12);
  ExpectItemEq<DummyCt>(cts, {"ct1<<=-12", "ct2<<=-12", "ct3<<=-12"});
}

TEST_F(TestWessVecCall, TestVecException) {
  std::vector<DummyPt> pts_vec = {DummyPt("1"), DummyPt("2"), DummyPt("3")};
  auto pts = Item::Ref(pts_vec, ContentType::Plaintext);
  std::vector<DummyCt> cts_vec = {DummyCt("1"), DummyCt("2")};
  auto cts = Item::Ref(cts_vec, ContentType::Ciphertext);

  EXPECT_ANY_THROW(we_->Add(cts, pts));
  EXPECT_ANY_THROW(we_->AddInplace(&cts, pts));
}

}  // namespace heu::lib::spi::test
