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

void PublicKey::Init(const BigInt &n, uint32_t s, const BigInt &hs) {
  n_ = n;
  s_ = s;
  hs_ = hs;
  pmod_ = n.Pow(s);
  cmod_ = pmod_ * n;
  bound_ = pmod_ / 2;

  if (hs.IsZero()) {
    BigInt x, gcd;
    do {
      x = BigInt::RandomLtN(n);
      gcd = x.Gcd(n);
    } while (gcd != 1);
    BigInt h = -x.MulMod(x, n);
    hs_ = h.PowMod(pmod_, cmod_);
  }

  lut_ = std::make_shared<LUT>();
  lut_->m_space = BigInt::CreateMontgomerySpace(cmod_);
  lut_->hs_pow = std::make_unique<BaseTable>();
  lut_->m_space->MakeBaseTable(hs_, kExpUnitBits, n_.BitCount() / 2,
                               lut_->hs_pow.get());
  lut_->n_pow.resize(s + 1);
  lut_->n_pow[0] = BigInt(1);
  lut_->precomp.resize(s + 1);
  lut_->precomp[0] = lut_->m_space->Identity();
  for (auto i = 1u; i <= s; ++i) {
    lut_->n_pow[i] = lut_->n_pow[i - 1] * n;
    lut_->precomp[i] = lut_->precomp[i - 1].MulMod(n, cmod_).MulMod(
        BigInt{i}.InvMod(cmod_), cmod_);
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

BigInt PublicKey::RandomHsR() const {
  BigInt r = BigInt::RandomExactBits(n_.BitCount() / 2);
  BigInt hs_r = lut_->m_space->PowMod(*lut_->hs_pow, r);
  return hs_r;
}

BigInt PublicKey::Encrypt(const BigInt &m) const {
  BigInt ctR{lut_->m_space->Identity()}, tmp{1}, prodR;
  for (auto i = 1u; i <= s_; ++i) {
    tmp = tmp.MulMod(m - (i - 1), lut_->n_pow[s_ - i + 1]);
    prodR = lut_->m_space->MulMod(MapIntoMSpace(tmp), lut_->precomp[i]);
    ctR += prodR;
  }
  return ctR % cmod_;
}

BigInt PublicKey::MapIntoMSpace(const BigInt &x) const {
  BigInt xR{x};
  lut_->m_space->MapIntoMSpace(xR);
  return xR;
}

BigInt PublicKey::MapBackToZSpace(const BigInt &xR) const {
  BigInt x{xR};
  lut_->m_space->MapBackToZSpace(x);
  return x;
}

}  // namespace heu::lib::algorithms::dj
