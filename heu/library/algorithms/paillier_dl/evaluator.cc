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

namespace heu::lib::algorithms::paillier_dl {

std::vector<Ciphertext> Evaluator::Add(const std::vector<Ciphertext>& as, const std::vector<Ciphertext>& bs) const {
  std::vector<Ciphertext> outs(as.size());

  CGBNWrapper::Add(pk_, as, bs, outs);

  return outs;
}

void Evaluator::AddInplace(std::vector<Ciphertext>& as, const std::vector<Ciphertext>& bs) const {
  CGBNWrapper::Add(pk_, as, bs, as);
}


std::vector<Ciphertext> Evaluator::Add(const std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const {
  std::vector<Plaintext> handled_bs = HandleNeg(bs);
  std::vector<Ciphertext> outs(as.size());

  CGBNWrapper::Add(pk_, as, handled_bs, outs); 

  return outs;
}

void Evaluator::AddInplace(std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const {
  std::vector<Plaintext> handled_bs = HandleNeg(bs);

  CGBNWrapper::Add(pk_, as, handled_bs, as); 
}

std::vector<Ciphertext> Evaluator::Sub(const std::vector<Ciphertext>& as, const std::vector<Ciphertext>& bs) const {
  return Add(as, Negate(bs));
}

void Evaluator::SubInplace(std::vector<Ciphertext>& as, const std::vector<Ciphertext>& bs) const {
  AddInplace(as, Negate(bs));
}

std::vector<Ciphertext> Evaluator::Sub(const std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const {
  std::vector<Plaintext> neg_bs;
  for (int i=0; i<bs.size(); i++) {
    Plaintext neg_b;
    bs[i].Negate(&neg_b);
    if (neg_b.IsNegative()) {
      neg_b += pk_.n_;
    }
    neg_bs.emplace_back(neg_b);
  }

  return Add(as, neg_bs);
}

void Evaluator::SubInplace(std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const {
  std::vector<Plaintext> neg_bs;
  for (int i=0; i<bs.size(); i++) {
    Plaintext neg_b;
    bs[i].Negate(&neg_b);
    if (neg_b.IsNegative()) {
      neg_b += pk_.n_;
    }
    neg_bs.emplace_back(neg_b);
  }

  AddInplace(as, neg_bs);
}

std::vector<Ciphertext> Evaluator::Mul(const std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const {
  std::vector<Plaintext> handled_bs = HandleNeg(bs);
  std::vector<Ciphertext> outs(as.size());

  CGBNWrapper::Mul(pk_, as, handled_bs, outs); 
  
  return outs;
}

void Evaluator::MulInplace(std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs) const {
  CGBNWrapper::Mul(pk_, as, bs, as); 
}

std::vector<Ciphertext> Evaluator::Negate(const std::vector<Ciphertext>& as) const {
  std::vector<Plaintext> bs;
  for (int i=0; i<as.size(); i++) {
    bs.emplace_back(MPInt(-1));
  }
  return Mul(as, bs);
}

void Evaluator::NegateInplace(std::vector<Ciphertext>& as) const {
  CGBNWrapper::Negate(pk_, as, as); 
}

}  // namespace heu::lib::algorithms::paillier_dl
