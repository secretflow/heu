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

#include "heu/library/algorithms/dj/public_key.h"

namespace heu::lib::algorithms::dj {

namespace {
constexpr size_t kExpUnitBits = 10;
}  // namespace

void PublicKey::Init(const MPInt &n, uint32_t s, const MPInt &hs) {
  n_ = n;
  s_ = s;
  hs_ = hs;
  pmod_ = n.Pow(s);
  cmod_ = pmod_ * n;
  bound_ = pmod_ / MPInt::_2_;

  if (hs.IsZero()) {
    MPInt x, h, gcd;
    do {
      MPInt::RandomLtN(n, &x);
      MPInt::Gcd(x, n, &gcd);
    } while (gcd != MPInt::_1_);
    h = x * x * -MPInt::_1_ % n;
    hs_ = h.PowMod(pmod_, cmod_);
  }

  lut_ = std::make_shared<LUT>();
  lut_->m_space = std::make_unique<MontgomerySpace>(cmod_);
  lut_->hs_pow = std::make_unique<BaseTable>();
  lut_->m_space->MakeBaseTable(hs_, kExpUnitBits, n_.BitCount() / 2,
                               lut_->hs_pow.get());
  lut_->n_pow.resize(s + 1);
  lut_->n_pow[0] = MPInt::_1_;
  lut_->precomp.resize(s + 1);
  lut_->precomp[0] = lut_->m_space->GetIdentity();
  for (auto i = 1u; i <= s; ++i) {
    lut_->n_pow[i] = lut_->n_pow[i - 1] * n;
    lut_->precomp[i] = lut_->precomp[i - 1].MulMod(n, cmod_).MulMod(
        MPInt{i}.InvertMod(cmod_), cmod_);
  }
}

bool PublicKey::operator==(const PublicKey &pk) const {
  return pmod_ == pk.pmod_ && hs_ == pk.hs_;
}

bool PublicKey::operator!=(const PublicKey &pk) const { return !(*this == pk); }

std::string PublicKey::ToString() const {
  return fmt::format(
      "Damgard-Jurik PK: n={}[{}bits], s={}, max_plaintext={}[~{}bits]",
      n_.ToHexString(), n_.BitCount(), s_, PlaintextBound().ToHexString(),
      PlaintextBound().BitCount());
}

MPInt PublicKey::RandomHsR() const {
  MPInt r, hs_r;
  MPInt::RandomExactBits(n_.BitCount() / 2, &r);
  lut_->m_space->PowMod(*lut_->hs_pow, r, &hs_r);
  return hs_r;
}

MPInt PublicKey::Encrypt(const MPInt &m) const {
  MPInt ctR{lut_->m_space->GetIdentity()}, tmp{1}, prodR;
  for (auto i = 1u; i <= s_; ++i) {
    MPInt::MulMod(tmp, m - MPInt{i - 1}, lut_->n_pow[s_ - i + 1], &tmp);
    lut_->m_space->MulMod(MapIntoMSpace(tmp), lut_->precomp[i], &prodR);
    ctR += prodR;
  }
  return ctR % cmod_;
}

MPInt PublicKey::MapIntoMSpace(const MPInt &x) const {
  MPInt xR{x};
  lut_->m_space->MapIntoMSpace(&xR);
  return xR;
}

MPInt PublicKey::MapBackToZSpace(const MPInt &xR) const {
  MPInt x{xR};
  lut_->m_space->MapBackToZSpace(&x);
  return x;
}

}  // namespace heu::lib::algorithms::dj
