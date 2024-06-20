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

#include "heu/library/algorithms/dgk/public_key.h"

namespace heu::lib::algorithms::dgk {

namespace {
constexpr size_t kExpUnitBits = 10;
constexpr size_t kRandExpBits = 400;  // 2.5t
}  // namespace

PublicKey::LUT::LUT(const PublicKey *pub) : m_space{pub->n_} {
  m_space.MakeBaseTable(pub->g_, kExpUnitBits, pub->u_.BitCount(), &g_pow);
  m_space.MakeBaseTable(pub->h_, kExpUnitBits, kRandExpBits, &h_pow);
}

void PublicKey::Init(const MPInt &n, const MPInt &g, const MPInt &h,
                     const MPInt &u) {
  n_ = n;
  g_ = g;
  h_ = h;
  u_ = u;
  lut_ = std::make_shared<LUT>(this);
}

bool PublicKey::operator==(const PublicKey &pk) const {
  return n_ == pk.n_ && g_ == pk.g_ && h_ == pk.h_ && u_ == pk.u_;
}

bool PublicKey::operator!=(const PublicKey &pk) const { return !(*this == pk); }

std::string PublicKey::ToString() const {
  return fmt::format(
      "Damgard-Geisler-Krøigaard PK: n={}[{}bits], g={}, h={}, u={}, "
      "max_plaintext={}[~{}bits]",
      n_.ToHexString(), n_.BitCount(), g_, h_, u_,
      PlaintextBound().ToHexString(), PlaintextBound().BitCount());
}

MPInt PublicKey::RandomHr() const {
  MPInt r, hr;
  MPInt::RandomExactBits(kRandExpBits, &r);
  lut_->m_space.PowMod(lut_->h_pow, r, &hr);
  return hr;
}

MPInt PublicKey::Encrypt(const MPInt &m) const {
  MPInt gm;
  lut_->m_space.PowMod(lut_->g_pow, m % u_, &gm);
  return gm;
}

MPInt PublicKey::MapIntoMSpace(const MPInt &x) const {
  MPInt xR{x};
  lut_->m_space.MapIntoMSpace(&xR);
  return xR;
}

MPInt PublicKey::MapBackToZSpace(const MPInt &xR) const {
  MPInt x{xR};
  lut_->m_space.MapBackToZSpace(&x);
  return x;
}

}  // namespace heu::lib::algorithms::dgk
