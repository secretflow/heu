// Copyright 2023 Denglin Co., Ltd.
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

#include "heu/library/algorithms/paillier_dl/evaluator.h"
#include "heu/library/algorithms/util/he_assert.h"
#include "heu/library/algorithms/paillier_dl/cgbn_wrapper/cgbn_wrapper.h"
#include "heu/library/algorithms/paillier_dl/utils.h"

namespace heu::lib::algorithms::paillier_dl {

std::vector<Ciphertext> Evaluator::Add(ConstSpan<Ciphertext> as, ConstSpan<Ciphertext> bs) const {
  std::vector<Ciphertext> as_vec;
  std::vector<Ciphertext> bs_vec;
  for (int i=0; i<as.size(); ++i) {
    as_vec.push_back(*as[i]);
    bs_vec.push_back(*bs[i]);
  }
  std::vector<Ciphertext> outs_vec(as_vec.size());

  CGBNWrapper::Add(pk_, as_vec, bs_vec, outs_vec);

  return outs_vec;
}

void Evaluator::AddInplace(Span<Ciphertext> as, ConstSpan<Ciphertext> bs) const {
  std::vector<Ciphertext> as_vec;
  std::vector<Ciphertext> bs_vec;
  for (int i=0; i<as.size(); ++i) {
    as_vec.push_back(*as[i]);
    bs_vec.push_back(*bs[i]);
  }
  std::vector<Ciphertext> outs_vec(as_vec.size());

  CGBNWrapper::Add(pk_, as_vec, bs_vec, as_vec);
  for (int i=0; i<as.size(); ++i) {
    *as[i] = as_vec[i];
  }
}

std::vector<Ciphertext> Evaluator::Add(ConstSpan<Ciphertext> as, ConstSpan<Plaintext> bs) const {
  std::vector<Ciphertext> as_vec;
  std::vector<Plaintext> bs_vec;
  for (int i=0; i<as.size(); ++i) {
    as_vec.push_back(*as[i]);
    bs_vec.push_back(*bs[i]);
  }
  std::vector<Plaintext> handled_bs_vec = HandleNeg(bs_vec);
  std::vector<Ciphertext> outs_vec(as_vec.size());

  CGBNWrapper::Add(pk_, as_vec, handled_bs_vec, outs_vec); 

  return outs_vec;
}

void Evaluator::AddInplace(Span<Ciphertext> as, ConstSpan<Plaintext> bs) const {
  std::vector<Ciphertext> as_vec;
  std::vector<Plaintext> bs_vec;
  for (int i=0; i<as.size(); ++i) {
    as_vec.push_back(*as[i]);
    bs_vec.push_back(*bs[i]);
  }
  std::vector<Plaintext> handled_bs_vec = HandleNeg(bs_vec);
  std::vector<Ciphertext> outs_vec(as_vec.size());

  CGBNWrapper::Add(pk_, as_vec, handled_bs_vec, as_vec); 
  for (int i=0; i<as.size(); ++i) {
    *as[i] = as_vec[i];
  }
}

std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Ciphertext> as, ConstSpan<Ciphertext> bs) const {
  auto neg_bs_vec = Negate(bs);
  std::vector<Ciphertext *> neg_bs_pt;
  ValueVecToPtsVec(neg_bs_vec, neg_bs_pt);
  auto neg_bs_span = absl::MakeConstSpan(neg_bs_pt.data(), neg_bs_vec.size());

  return Add(as, neg_bs_span);
}

void Evaluator::SubInplace(Span<Ciphertext> as, ConstSpan<Ciphertext> bs) const {
  auto neg_bs_vec = Negate(bs);
  std::vector<Ciphertext *> neg_bs_pt;
  ValueVecToPtsVec(neg_bs_vec, neg_bs_pt);
  auto neg_bs_span = absl::MakeConstSpan(neg_bs_pt.data(), neg_bs_vec.size());

  AddInplace(as, neg_bs_span);
}

std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Ciphertext> as, ConstSpan<Plaintext> bs) const {
  std::vector<Plaintext> neg_bs_vec;
  for (int i=0; i<bs.size(); i++) {
    Plaintext neg_b;
    bs[i]->Negate(&neg_b);
    neg_bs_vec.emplace_back(neg_b);
  }
  std::vector<Plaintext *> neg_bs_pt;
  ValueVecToPtsVec(neg_bs_vec, neg_bs_pt);
  auto neg_bs_span = absl::MakeConstSpan(neg_bs_pt.data(), neg_bs_vec.size());

  return Add(as, neg_bs_span);
}

void Evaluator::SubInplace(Span<Ciphertext> as, ConstSpan<Plaintext> bs) const {
  std::vector<Plaintext> neg_bs_vec;
  for (int i=0; i<bs.size(); i++) {
    Plaintext neg_b;
    bs[i]->Negate(&neg_b);
    neg_bs_vec.emplace_back(neg_b);
  }
  std::vector<Plaintext *> neg_bs_pt;
  ValueVecToPtsVec(neg_bs_vec, neg_bs_pt);
  auto neg_bs_span = absl::MakeConstSpan(neg_bs_pt.data(), neg_bs_vec.size());

  AddInplace(as, neg_bs_span);
}

std::vector<Ciphertext> Evaluator::Mul(ConstSpan<Ciphertext> as, ConstSpan<Plaintext> bs) const {
  std::vector<Ciphertext> as_vec;
  std::vector<Plaintext> bs_vec;
  for (int i=0; i<as.size(); ++i) {
    as_vec.push_back(*as[i]);
    bs_vec.push_back(*bs[i]);
  }

  std::vector<Plaintext> handled_bs_vec = HandleNeg(bs_vec);
  std::vector<Ciphertext> outs_vec(as_vec.size());

  CGBNWrapper::Mul(pk_, as_vec, handled_bs_vec, outs_vec); 
  
  return outs_vec;
}

void Evaluator::MulInplace(Span<Ciphertext> as, ConstSpan<Plaintext> bs) const {
  std::vector<Ciphertext> as_vec;
  std::vector<Plaintext> bs_vec;
  for (int i=0; i<as.size(); ++i) {
    as_vec.push_back(*as[i]);
    bs_vec.push_back(*bs[i]);
  }
  std::vector<Plaintext> handled_bs_vec = HandleNeg(bs_vec);
  std::vector<Ciphertext> outs_vec(as_vec.size());

  CGBNWrapper::Mul(pk_, as_vec, handled_bs_vec, as_vec);
  for (int i=0; i<as.size(); ++i) {
    *as[i] = as_vec[i];
  }
}

std::vector<Ciphertext> Evaluator::Negate(ConstSpan<Ciphertext> as) const {
  std::vector<Plaintext> bs_vec;
  for (int i=0; i<as.size(); i++) {
    bs_vec.emplace_back(MPInt(-1));
  }
  std::vector<Plaintext *> bs_pt;
  ValueVecToPtsVec(bs_vec, bs_pt);
  auto bs_span = absl::MakeConstSpan(bs_pt.data(), bs_vec.size());

  return Mul(as, bs_span);
}

void Evaluator::NegateInplace(Span<Ciphertext> as) const {
  std::vector<Plaintext> bs_vec;
  for (int i=0; i<as.size(); i++) {
    bs_vec.emplace_back(MPInt(-1));
  }
  std::vector<Plaintext *> bs_pt;
  ValueVecToPtsVec(bs_vec, bs_pt);
  auto bs_span = absl::MakeConstSpan(bs_pt.data(), bs_vec.size());

  auto res_vec = Mul(as, bs_span);
  for (int i=0; i<as.size(); ++i) {
    *as[i] = res_vec[i];
  }
}

}  // namespace heu::lib::algorithms::paillier_dl
