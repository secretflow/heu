// Copyright 2023 zhangwfjh
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

#include "heu/library/algorithms/dj/secret_key.h"

namespace heu::lib::algorithms::dj {

void SecretKey::Init(MPInt const& p, MPInt const& q, uint32_t s) {
  auto n{p * q};
  n_ = {p, q};
  s_ = s;
  pmod_ = n.Pow(s);
  lambda_ = ((p - MPInt::_1_) * (q - MPInt::_1_) / MPInt::_2_);
  mu_ = lambda_.InvertMod(pmod_);

  lut_ = std::make_shared<LUT>();
  lut_->pq_pow.resize(s + 2);
  lut_->pq_pow[1] = {p, q};
  for (auto i = 2u; i <= s + 1; ++i) {
    lut_->pq_pow[i] = {lut_->pq_pow[i - 1].P * p, lut_->pq_pow[i - 1].Q * q};
  }
  auto const& [ps, qs] = lut_->pq_pow[s];
  pp_ = ps * ps.InvertMod(qs);
  inv_pq_ = {q.InvertMod(ps), p.InvertMod(qs)};
  lut_->precomp.resize(s + 1);
  for (auto j = 2u; j <= s; ++j) {
    lut_->precomp[j].resize(j + 1);
  }
  if (s > 1) {
    lut_->precomp[s][1] = {MPInt::_1_, MPInt::_1_};
  }
  for (auto i = 2u; i <= s; ++i) {
    for (auto j = i; j <= s; ++j) {
      lut_->precomp[j][i] = {lut_->precomp[s][i - 1].P.MulMod(n, ps).MulMod(
                                 MPInt{i}.InvertMod(ps), ps),
                             lut_->precomp[s][i - 1].Q.MulMod(n, qs).MulMod(
                                 MPInt{i}.InvertMod(qs), qs)};
    }
  }
}

bool SecretKey::operator==(const SecretKey& sk) const {
  return pmod_ == sk.pmod_;
}

bool SecretKey::operator!=(const SecretKey& sk) const { return !(*this == sk); }

std::string SecretKey::ToString() const {
  return fmt::format("Damgard-Jurik SK: p={}[{}bits], q={}[{}bits], s={}",
                     n_.P.ToHexString(), n_.P.BitCount(), n_.Q.ToHexString(),
                     n_.Q.BitCount(), s_);
}

MPInt SecretKey::Decrypt(const MPInt& ct) const {
  MPInt2 z, ls;
  // compute z = c^d mod n^(s+1)
  auto const& [ps1, qs1] = lut_->pq_pow[s_ + 1];
  z = {(ct % ps1).PowMod(lambda_, ps1), (ct % qs1).PowMod(lambda_, qs1)};
  //  compute ls = L(z) mod n^s
  auto const& [ps, qs] = lut_->pq_pow[s_];
  ls = {inv_pq_.P.MulMod((z.P - MPInt::_1_) / n_.P, ps),
        inv_pq_.Q.MulMod((z.Q - MPInt::_1_) / n_.Q, qs)};

  MPInt2 ind{ls.P % lut_->pq_pow[1].P, ls.Q % lut_->pq_pow[1].Q};
  MPInt2 l, tmp;
  for (auto j = 2u; j <= s_; ++j) {
    // compute l = L(c^d mod n^{j+1}) mod n^j = ls mod n^j
    l = {ls.P % lut_->pq_pow[j].P, ls.Q % lut_->pq_pow[j].Q};
    // compute ind mod n^j
    tmp = ind;
    for (auto i = 2u; i <= j; ++i) {
      MPInt::MulMod(tmp.P, ind.P - MPInt{i - 1}, lut_->pq_pow[j - i + 1].P,
                    &tmp.P);
      MPInt::MulMod(tmp.Q, ind.Q - MPInt{i - 1}, lut_->pq_pow[j - i + 1].Q,
                    &tmp.Q);
      l.P -= tmp.P.MulMod(lut_->precomp[j][i].P, lut_->pq_pow[j].P);
      l.Q -= tmp.Q.MulMod(lut_->precomp[j][i].Q, lut_->pq_pow[j].Q);
    }
    ind = {l.P % lut_->pq_pow[j].P, l.Q % lut_->pq_pow[j].Q};
  }
  auto m_lambda = (ind.P + (ind.Q - ind.P) * pp_) % pmod_;
  return m_lambda.MulMod(mu_, pmod_);
}

}  // namespace heu::lib::algorithms::dj
