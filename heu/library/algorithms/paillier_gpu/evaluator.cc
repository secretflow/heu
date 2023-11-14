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

#include "heu/library/algorithms/paillier_gpu/evaluator.h"

#include "heu/library/algorithms/util/he_assert.h"

namespace heu::lib::algorithms::paillier_g {

void Evaluator::Randomize(Span<Ciphertext> ct) const {
  unsigned int count = ct.size();
  // make the constspan of enc(0)
  std::vector<Ciphertext> res = encryptor_.EncryptZero(count);
  Ciphertext* ccts[count];
  for (unsigned int i = 0; i < count; i++) {
    ccts[i] = &res[i];
  }
  ConstSpan<Ciphertext> cpts = absl::MakeConstSpan(ccts, count);
  AddInplace(ct, cpts);
}

std::vector<Ciphertext> Evaluator::Add(ConstSpan<Ciphertext> ct0,
                                       ConstSpan<Ciphertext> ct1) const {
  // a. pubkey;
  h_paillier_pubkey_t g_pk;
  pk_.n_.ToBytes(g_pk.n, 512, algorithms::Endian::little);
  pk_.n_square_.ToBytes(g_pk.n_squared, 512, algorithms::Endian::little);
  pk_.n_plus_.ToBytes(g_pk.n_plusone, 512, algorithms::Endian::little);

  // b. batch size;
  unsigned int count = ct0.size();

  // c. Host memory
  auto res = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gct0 = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gct1 = std::make_unique<h_paillier_ciphertext_t[]>(count);
  for (unsigned int i = 0; i < count; i++) {
    gct0[i] = ct0[i]->ct_;
    gct1[i] = ct1[i]->ct_;
  }
  // d. GPU do cipher add
  gpu_paillier_e_add(&g_pk, res.get(), gct0.get(), gct1.get(), count);

  // e. to vector<Ciphertext>
  std::vector<Ciphertext> ctx_res(count);
  for (unsigned int i = 0; i < count; i++) {
    ctx_res[i].ct_ = res[i];
  }

  return ctx_res;
}

void Evaluator::AddInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const {
  std::vector<Ciphertext> sum = Add(a, b);
  for (unsigned int i = 0; i < a.size(); i++) *a[i] = sum[i];
}

std::vector<Plaintext> Evaluator::Add(ConstSpan<Plaintext> a,
                                      ConstSpan<Plaintext> b) const {
  std::vector<Plaintext> pts(a.size(), Plaintext(0));
  for (unsigned int i = 0; i <= a.size() - 1; i++)
    pts[i] = (Plaintext)(*a[i] + *b[i]);
  return pts;
}

void Evaluator::AddInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const {
  std::vector<Plaintext> pts(a.size(), Plaintext(0));
  pts = Evaluator::Add(a, b);
  for (unsigned int i = 0; i <= a.size() - 1; i++) *a[i] = pts[i];
}

std::vector<Ciphertext> Evaluator::Add(ConstSpan<Ciphertext> cts,
                                       ConstSpan<Plaintext> pts) const {
  // a. pubkey
  h_paillier_pubkey_t g_pk;
  pk_.n_.ToBytes(g_pk.n, 512, algorithms::Endian::little);
  pk_.n_square_.ToBytes(g_pk.n_squared, 512, algorithms::Endian::little);
  pk_.n_plus_.ToBytes(g_pk.n_plusone, 512, algorithms::Endian::little);

  // b. batch size;
  unsigned int count = cts.size();

  // c. Host memory
  auto res = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gct0 = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gpts = std::make_unique<h_paillier_plaintext_t[]>(count);

  for (unsigned int i = 0; i < count; i++) {
    gct0[i] = cts[i]->ct_;
    Plaintext temp;
    if (pts[i]->IsNegative()) {
      temp = (Plaintext)(*pts[i] + pk_.n_);
      temp.ToBytes(gpts[i].m, 512, algorithms::Endian::little);
    } else {
      pts[i]->ToBytes(gpts[i].m, 512, algorithms::Endian::little);
    }
  }

  // d.GPU do
  gpu_paillier_e_add_const(&g_pk, res.get(), gct0.get(), gpts.get(), count);

  // e. to std::vector<Ciphertext>
  std::vector<Ciphertext> ctx_res(count);
  for (unsigned int i = 0; i < count; i++) {
    ctx_res[i].ct_ = res[i];
  }

  return ctx_res;
}

std::vector<Ciphertext> Evaluator::Add(ConstSpan<Plaintext> pts,
                                       ConstSpan<Ciphertext> cts) const {
  return Add(cts, pts);
}

// AddInplace
void Evaluator::AddInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const {
  std::vector<Ciphertext> sum = Add(a, b);
  for (unsigned int i = 0; i < a.size(); i++) *a[i] = sum[i];
}

/* ------------------ mul   ------------------ */
std::vector<Ciphertext> Evaluator::Mul(ConstSpan<Ciphertext> cts,
                                       ConstSpan<Plaintext> pts) const {
  // a. pubkey
  h_paillier_pubkey_t g_pk;
  pk_.n_.ToBytes(g_pk.n, 512, algorithms::Endian::little);
  pk_.n_square_.ToBytes(g_pk.n_squared, 512, algorithms::Endian::little);
  pk_.n_plus_.ToBytes(g_pk.n_plusone, 512, algorithms::Endian::little);

  // b. batch size;
  unsigned int count = cts.size();

  // c. host memory
  auto res = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gct0 = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gpts = std::make_unique<h_paillier_plaintext_t[]>(count);

  for (unsigned int i = 0; i < count; i++) {
    gct0[i] = cts[i]->ct_;
    if (pts[i]->IsNegative()) {
      Plaintext temp;
      temp = (Plaintext)(*pts[i] + pk_.n_);
      temp.ToBytes(gpts[i].m, 512, algorithms::Endian::little);
    } else {
      pts[i]->ToBytes(gpts[i].m, 512, algorithms::Endian::little);
    }
  }
  // d. GPU do
  gpu_paillier_e_mul_const(&g_pk, res.get(), gct0.get(), gpts.get(), count);

  // e. to std::vector<Ciphertext>
  std::vector<Ciphertext> ctx_res(count);
  for (unsigned int i = 0; i < count; i++) {
    ctx_res[i].ct_ = res[i];
  }

  return ctx_res;
}

std::vector<Ciphertext> Evaluator::Mul(ConstSpan<Plaintext> pts,
                                       ConstSpan<Ciphertext> cts) const {
  return Mul(cts, pts);
}

std::vector<Plaintext> Evaluator::Mul(ConstSpan<Plaintext> pts1,
                                      ConstSpan<Plaintext> pts2) const {
  unsigned int count = pts1.size();
  std::vector<Plaintext> res(count);
  for (unsigned int i = 0; i < count; i++)
    res[i] = (Plaintext)((*pts1[i]) * (*pts2[i]));
  return res;
}

void Evaluator::MulInplace(Span<Ciphertext> cts,
                           ConstSpan<Plaintext> pts) const {
  std::vector<Ciphertext> vec = Mul(cts, pts);
  for (unsigned int i = 0; i < cts.size(); i++) *cts[i] = vec[i];
}

void Evaluator::MulInplace(Span<Plaintext> pts1,
                           ConstSpan<Plaintext> pts2) const {
  unsigned int count = pts1.size();
  std::vector<Plaintext> res(count);
  for (unsigned int i = 0; i < count; i++) (*pts1[i]) *= (*pts2[i]);
}

/*                        Sub                         */
std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Ciphertext> cts0,
                                       ConstSpan<Ciphertext> cts1) const {
  // a. pubkey;
  h_paillier_pubkey_t g_pk;
  pk_.n_.ToBytes(g_pk.n, 512, algorithms::Endian::little);
  pk_.n_square_.ToBytes(g_pk.n_squared, 512, algorithms::Endian::little);
  pk_.n_plus_.ToBytes(g_pk.n_plusone, 512, algorithms::Endian::little);

  // b. batch size;
  unsigned int count = cts1.size();

  // c. Host memory
  auto res = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gct0 = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gct1 = std::make_unique<h_paillier_ciphertext_t[]>(count);

  for (unsigned int i = 0; i < count; i++) {
    gct0[i] = cts0[i]->ct_;
    gct1[i] = cts1[i]->ct_;
  }
  // d. GPU do cipher add
  gpu_paillier_sub_ct(&g_pk, res.get(), gct0.get(), gct1.get(), count);

  // e. to vector<Ciphertext>
  std::vector<Ciphertext> ctx_res(count);
  for (unsigned int i = 0; i < count; i++) {
    ctx_res[i].ct_ = res[i];
  }

  return ctx_res;
}

std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Ciphertext> cts,
                                       ConstSpan<Plaintext> pts) const {
  // a. pubkey;
  h_paillier_pubkey_t g_pk;
  pk_.n_.ToBytes(g_pk.n, 512, algorithms::Endian::little);
  pk_.n_square_.ToBytes(g_pk.n_squared, 512, algorithms::Endian::little);
  pk_.n_plus_.ToBytes(g_pk.n_plusone, 512, algorithms::Endian::little);

  // b. batch size;
  unsigned int count = cts.size();

  // c. Host memory
  auto res = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gct = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gpt = std::make_unique<h_paillier_plaintext_t[]>(count);

  for (unsigned int i = 0; i < count; i++) {
    gct[i] = cts[i]->ct_;
    // Negative numbers should be handled
    if (pts[i]->IsNegative()) {
      Plaintext temp;
      temp = (Plaintext)(*pts[i] + pk_.n_);
      temp.ToBytes(gpt[i].m, 512, algorithms::Endian::little);
    } else {
      pts[i]->ToBytes(gpt[i].m, 512, algorithms::Endian::little);
    }
  }
  // d. GPU do cipher add
  gpu_paillier_sub_ctpt(&g_pk, res.get(), gct.get(), gpt.get(), count);

  // e. to vector<Ciphertext>
  std::vector<Ciphertext> ctx_res(count);
  for (unsigned int i = 0; i < count; i++) {
    ctx_res[i].ct_ = res[i];
  }

  return ctx_res;
}

std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Plaintext> pts,
                                       ConstSpan<Ciphertext> cts) const {
  // a. pubkey;
  h_paillier_pubkey_t g_pk;
  pk_.n_.ToBytes(g_pk.n, 512, algorithms::Endian::little);
  pk_.n_square_.ToBytes(g_pk.n_squared, 512, algorithms::Endian::little);
  pk_.n_plus_.ToBytes(g_pk.n_plusone, 512, algorithms::Endian::little);

  // b. batch size;
  unsigned int count = pts.size();

  // c. Host memory
  auto res = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gct = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gpt = std::make_unique<h_paillier_plaintext_t[]>(count);

  for (unsigned int i = 0; i < count; i++) {
    gct[i] = cts[i]->ct_;
    // Negative numbers should be handled
    if (pts[i]->IsNegative()) {
      Plaintext temp;
      temp = (Plaintext)(*pts[i] + pk_.n_);
      temp.ToBytes(gpt[i].m, 512, algorithms::Endian::little);
    } else {
      pts[i]->ToBytes(gpt[i].m, 512, algorithms::Endian::little);
    }
  }
  // d. GPU do cipher add
  gpu_paillier_sub_ptct(&g_pk, res.get(), gpt.get(), gct.get(), count);

  // e. to vector<Ciphertext>
  std::vector<Ciphertext> ctx_res(count);
  for (unsigned int i = 0; i < count; i++) {
    ctx_res[i].ct_ = res[i];
  }

  return ctx_res;
}

std::vector<Plaintext> Evaluator::Sub(ConstSpan<Plaintext> pts1,
                                      ConstSpan<Plaintext> pts2) const {
  unsigned int count = pts1.size();
  std::vector<Plaintext> res(count);
  for (unsigned int i = 0; i < count; i++) {
    res[i] = (Plaintext)(*pts1[i] - *pts2[i]);
  }
  return res;
}

void Evaluator::SubInplace(Span<Ciphertext> cts1,
                           ConstSpan<Ciphertext> cts2) const {
  std::vector<Ciphertext> res = Sub(cts1, cts2);
  unsigned int count = cts1.size();
  for (unsigned int i = 0; i < count; i++) {
    *cts1[i] = res[i];
  }
}

void Evaluator::SubInplace(Span<Ciphertext> cts,
                           ConstSpan<Plaintext> pts) const {
  std::vector<Ciphertext> res = Sub(cts, pts);
  unsigned int count = cts.size();
  for (unsigned int i = 0; i < count; i++) {
    *cts[i] = res[i];
  }
}

void Evaluator::SubInplace(Span<Plaintext> pts1,
                           ConstSpan<Plaintext> pts2) const {
  std::vector<Plaintext> res = Sub(pts1, pts2);
  unsigned int count = pts1.size();
  for (unsigned int i = 0; i < count; i++) {
    *pts1[i] = res[i];
  }
}

std::vector<Ciphertext> Evaluator::Negate(ConstSpan<Ciphertext> cts) const {
  // a. pub_k
  h_paillier_pubkey_t g_pk;
  pk_.n_.ToBytes(g_pk.n, 512, algorithms::Endian::little);
  pk_.n_square_.ToBytes(g_pk.n_squared, 512, algorithms::Endian::little);
  pk_.n_plus_.ToBytes(g_pk.n_plusone, 512, algorithms::Endian::little);

  // b. batch size
  unsigned int count = cts.size();

  // c. Host memory
  auto res = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gct0 = std::make_unique<h_paillier_ciphertext_t[]>(count);

  for (unsigned int i = 0; i < count; i++) {
    gct0[i] = cts[i]->ct_;
  }
  // d. GPU do
  gpu_paillier_e_inverse(&g_pk, res.get(), gct0.get(), count);
  // e. to Vector
  std::vector<Ciphertext> ctx_res(count);
  for (unsigned int i = 0; i < count; i++) {
    ctx_res[i].ct_ = res[i];
  }

  return ctx_res;
}

void Evaluator::NegateInplace(Span<Ciphertext> cts) const {
  std::vector<Ciphertext> ctx_res = Negate(cts);

  unsigned int count = cts.size();
  for (unsigned int i = 0; i < count; i++) {
    *cts[i] = ctx_res[i];
  }
}

}  // namespace heu::lib::algorithms::paillier_g
