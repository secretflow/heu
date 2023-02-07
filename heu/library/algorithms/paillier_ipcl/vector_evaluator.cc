// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "heu/library/algorithms/paillier_ipcl/vector_evaluator.h"

#include <iostream>

#include "heu/library/algorithms/paillier_ipcl/utils.h"
#include "heu/library/algorithms/util/he_assert.h"
namespace heu::lib::algorithms::paillier_ipcl {

Evaluator::Evaluator(const PublicKey& pk) : pk_(pk) {}

void Evaluator::Randomize(Span<Ciphertext> ct) const {
  size_t size = ct.size();
  std::vector<BigNumber> bn_zeros(size, BigNumber::Zero());
  ipcl::PlainText pt_zeros(bn_zeros);
  ipcl::CipherText ct_zeros = pk_.ipcl_pubkey_.encrypt(pt_zeros);
  auto ct_zeros_vec = IpclToHeu<Ciphertext, ipcl::CipherText>(ct_zeros);
  std::vector<Ciphertext*> ct_zeros_pts;
  ValueVecToPtsVec(ct_zeros_vec, ct_zeros_pts);
  ConstSpan<Ciphertext> ct_zeros_span =
      absl::MakeConstSpan(ct_zeros_pts.data(), size);
  AddInplace(ct, ct_zeros_span);
}

std::vector<Ciphertext> Evaluator::Add(ConstSpan<Ciphertext> a,
                                       ConstSpan<Ciphertext> b) const {
  HE_ASSERT(a.size() == b.size(), "CT + CT error: size mismatch.");
  ipcl::CipherText ipcl_ct_a = ToIpclCiphertext(pk_, a);
  ipcl::CipherText ipcl_ct_b = ToIpclCiphertext(pk_, b);
  auto sum = ipcl_ct_a + ipcl_ct_b;
  return IpclToHeu<Ciphertext, ipcl::CipherText>(sum);
}

std::vector<Ciphertext> Evaluator::Add(ConstSpan<Ciphertext> a,
                                       ConstSpan<Plaintext> b) const {
  HE_ASSERT(a.size() == b.size(), "CT + PT error: size mismatch.");
  ipcl::CipherText ipcl_ct_a = ToIpclCiphertext(pk_, a);
  ipcl::PlainText ipcl_pt_b = ToIpclPlaintext(b);
  auto sum = ipcl_ct_a + ipcl_pt_b;
  return IpclToHeu<Ciphertext, ipcl::CipherText>(sum);
}

std::vector<Ciphertext> Evaluator::Add(ConstSpan<Plaintext> a,
                                       ConstSpan<Ciphertext> b) const {
  return Add(b, a);
}

std::vector<Plaintext> Evaluator::Add(ConstSpan<Plaintext> a,
                                      ConstSpan<Plaintext> b) const {
  HE_ASSERT(a.size() == b.size(), "PT + PT error: size mismatch.");
  std::vector<Plaintext> sum;
  size_t vec_size = a.size();
  for (size_t i = 0; i < vec_size; i++) {
    sum.push_back(*a[i] + *b[i]);
  }
  return sum;
}

void Evaluator::AddInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const {
  auto sum = Add(a, b);
  size_t vec_size = sum.size();
  for (size_t i = 0; i < vec_size; i++) {
    *a[i] = sum[i];
  }
}

void Evaluator::AddInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const {
  auto sum = Add(a, b);
  size_t vec_size = sum.size();
  for (size_t i = 0; i < vec_size; i++) {
    *a[i] = sum[i];
  }
}

void Evaluator::AddInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const {
  auto sum = Add(a, b);
  size_t vec_size = sum.size();
  for (size_t i = 0; i < vec_size; i++) {
    *a[i] = sum[i];
  }
}

std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Ciphertext> a,
                                       ConstSpan<Ciphertext> b) const {
  HE_ASSERT(a.size() == b.size(), "CT - CT error: size mismatch.");
  std::vector<Ciphertext> neg_b_vec = Negate(b);
  std::vector<Ciphertext*> neg_b_pts;
  ValueVecToPtsVec(neg_b_vec, neg_b_pts);
  ConstSpan<Ciphertext> neg_b_span =
      absl::MakeConstSpan(neg_b_pts.data(), neg_b_pts.size());
  return Add(a, neg_b_span);
}

std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Ciphertext> a,
                                       ConstSpan<Plaintext> b) const {
  HE_ASSERT(a.size() == b.size(), "CT - PT error: size mismatch.");
  std::vector<Plaintext> neg_b_vec;
  for (auto item : b) {
    neg_b_vec.push_back(-(*item));
  }
  std::vector<Plaintext*> neg_b_pts;
  ValueVecToPtsVec(neg_b_vec, neg_b_pts);
  ConstSpan<Plaintext> neg_b_span =
      absl::MakeConstSpan(neg_b_pts.data(), neg_b_pts.size());
  return Add(a, neg_b_span);
}

std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Plaintext> a,
                                       ConstSpan<Ciphertext> b) const {
  HE_ASSERT(a.size() == b.size(), "PT - CT error: size mismatch.");
  std::vector<Ciphertext> neg_b_vec = Negate(b);
  std::vector<Ciphertext*> neg_b_pts;
  ValueVecToPtsVec(neg_b_vec, neg_b_pts);
  ConstSpan<Ciphertext> neg_b_span =
      absl::MakeConstSpan(neg_b_pts.data(), neg_b_pts.size());
  return Add(a, neg_b_span);
}

std::vector<Plaintext> Evaluator::Sub(ConstSpan<Plaintext> a,
                                      ConstSpan<Plaintext> b) const {
  HE_ASSERT(a.size() == b.size(), "PT - PT error: size mismatch.");
  size_t size = a.size();
  std::vector<Plaintext> result;
  for (size_t i = 0; i < size; i++) {
    result.push_back(*a[i] - *b[i]);
  }
  return result;
}

void Evaluator::SubInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const {
  auto res = Sub(a, b);
  size_t vec_size = res.size();
  for (size_t i = 0; i < vec_size; i++) {
    *a[i] = res[i];
  }
}
void Evaluator::SubInplace(Span<Ciphertext> a, ConstSpan<Plaintext> p) const {
  auto res = Sub(a, p);
  size_t vec_size = res.size();
  for (size_t i = 0; i < vec_size; i++) {
    *a[i] = res[i];
  }
}
void Evaluator::SubInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const {
  auto res = Sub(a, b);
  size_t vec_size = res.size();
  for (size_t i = 0; i < vec_size; i++) {
    *a[i] = res[i];
  }
}

std::vector<Ciphertext> Evaluator::Mul(ConstSpan<Ciphertext> a,
                                       ConstSpan<Plaintext> b) const {
  HE_ASSERT((a.size() == b.size() || b.size() == 1),
            "CT * PT error: size mismatch.");
  std::vector<BigNumber> a_bn;
  std::vector<BigNumber> b_bn;
  size_t size = a.size();
  auto n_sqr = pk_.ipcl_pubkey_.getNSQ();
  if (b.size() == 1) {
    bool is_b_neg = b[0]->IsNegative();
    if (is_b_neg) {
      b_bn.push_back(-(*b[0]));
      for (size_t i = 0; i < size; i++) {
        a_bn.push_back(n_sqr->InverseMul(a[i]->bn_));
      }
    } else {
      b_bn.push_back(b[0]->bn_);
      for (size_t i = 0; i < size; i++) {
        a_bn.push_back(a[i]->bn_);
      }
    }
  } else {
    for (size_t i = 0; i < size; i++) {
      if (b[i]->IsNegative()) {
        a_bn.push_back(n_sqr->InverseMul(a[i]->bn_));
        b_bn.push_back(-(*b[i]));
      } else {
        a_bn.push_back(a[i]->bn_);
        b_bn.push_back(b[i]->bn_);
      }
    }
  }

  ipcl::CipherText ipcl_ct_a(pk_.ipcl_pubkey_, a_bn);
  ipcl::PlainText ipcl_pt_b(b_bn);
  auto product = ipcl_ct_a * ipcl_pt_b;
  return IpclToHeu<Ciphertext, ipcl::CipherText>(product);
}

std::vector<Ciphertext> Evaluator::Mul(ConstSpan<Plaintext> a,
                                       ConstSpan<Ciphertext> b) const {
  return Mul(b, a);
}

std::vector<Plaintext> Evaluator::Mul(ConstSpan<Plaintext> a,
                                      ConstSpan<Plaintext> b) const {
  HE_ASSERT((a.size() == b.size() || b.size() == 1),
            "PT * PT error: size mismatch.");
  std::vector<Plaintext> product;
  size_t vec_size = a.size();
  if (b.size() == 1) {
    for (size_t i = 0; i < vec_size; i++) {
      product.push_back(*a[i] * *b[0]);
    }
  } else {
    for (size_t i = 0; i < vec_size; i++) {
      product.push_back(*a[i] * *b[i]);
    }
  }
  return product;
}

void Evaluator::MulInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const {
  auto product = Mul(a, b);
  size_t vec_size = product.size();
  for (size_t i = 0; i < vec_size; i++) {
    *a[i] = product[i];
  }
}

void Evaluator::MulInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const {
  auto product = Mul(a, b);
  size_t vec_size = product.size();
  for (size_t i = 0; i < vec_size; i++) {
    *a[i] = product[i];
  }
}

std::vector<Ciphertext> Evaluator::Negate(ConstSpan<Ciphertext> a) const {
  Plaintext pt_neg_one;
  pt_neg_one.Set(-1);
  std::vector<Plaintext*> pts_neg_one;
  pts_neg_one.push_back(&pt_neg_one);
  ConstSpan<Plaintext> span_neg_one =
      absl::MakeConstSpan(pts_neg_one.data(), 1);
  std::vector<Ciphertext> result;
  result = Mul(a, span_neg_one);
  return result;
}

void Evaluator::NegateInplace(Span<Ciphertext> a) const {
  auto neg_a = Negate(a);
  size_t vec_size = neg_a.size();
  for (size_t i = 0; i < vec_size; i++) {
    *a[i] = neg_a[i];
  }
}
}  // namespace heu::lib::algorithms::paillier_ipcl
