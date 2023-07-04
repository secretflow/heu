// Copyright 2022 Ant Group Co., Ltd.
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

#include "heu/library/algorithms/ou/encryptor.h"

#include "fmt/compile.h"

namespace heu::lib::algorithms::ou {

Encryptor::Encryptor(PublicKey pk, bool enable_cache)
    : pk_(std::move(pk)), enable_cache_(enable_cache) {
  cache_hr_ = std::make_shared<MPInt>();
  cache_r_ = std::make_shared<MPInt>();

  // threshold 2560 is the mid of 2048, 3072
  if (pk_.n_.BitCount() >= 2560) {
    random_bits_ = internal_params::kRandomBits3072;
  } else if (pk_.n_.BitCount() >= 1536) {
    random_bits_ = internal_params::kRandomBits2048;
  } else {
    random_bits_ = internal_params::kRandomBits1024;
  }
}

Encryptor::Encryptor(const Encryptor &from)
    : Encryptor(from.pk_, from.enable_cache_) {}

// calc H^r
// r is a random number < n
// H and n is public key
MPInt Encryptor::GetHr() const {
  if (enable_cache_) {
    return *GetHrUsingCache();
  } else {
    MPInt r;
    MPInt::RandomExactBits(random_bits_, &r);
    MPInt hr;
    pk_.m_space_->PowMod(*pk_.ch_table_, r, &hr);
    return hr;
  }
}

// calc H^r using cache
// detail:
// we re-use previous calculated H^(r_old)
// and choose another small random number r_small,
// the final H^r = H^(r_old) * H^(r_small)
std::shared_ptr<MPInt> Encryptor::GetHrUsingCache() const {
  bool reset;
  std::shared_ptr<MPInt> cache_hr;
  std::shared_ptr<MPInt> cache_r;
  {
    std::unique_lock<std::mutex> lock(hr_mutex_);
    auto r_bits = cache_r_->BitCount();
    reset = r_bits < internal_params::kRandomBits3072 ||
            r_bits >= pk_.n_.BitCount() - 1;
    if (!reset) {
      cache_hr = cache_hr_;
      cache_r = cache_r_;
    }
  }

  if (reset) {
    // cannot use cache, too small or too big, gen a new H^r
    auto r = std::make_shared<MPInt>();
    MPInt::RandomExactBits(internal_params::kRandomBits3072, r.get());
    auto new_hr = std::make_shared<MPInt>();
    pk_.m_space_->PowMod(*pk_.ch_table_, *r, new_hr.get());

    // update cache
    std::unique_lock<std::mutex> lock(hr_mutex_);
    cache_r_ = r;
    cache_hr_ = new_hr;
    return new_hr;
  }

  // gen small r
  auto delta_r = std::make_shared<MPInt>();
  MPInt::RandomExactBits(random_bits_, delta_r.get());
  MPInt delta_hr;  // delta_hr = H^(delta_r)
  pk_.m_space_->PowMod(*pk_.ch_table_, *delta_r, &delta_hr);
  // new_H^r = H^(r_cache) * H^(delta_r)
  auto new_hr = std::make_shared<MPInt>();
  pk_.m_space_->MulMod(*cache_hr, delta_hr, new_hr.get());

  // update cache
  *delta_r += *cache_r;
  std::unique_lock<std::mutex> lock(hr_mutex_);
  cache_r_ = delta_r;
  cache_hr_ = new_hr;
  return new_hr;
}

Ciphertext Encryptor::EncryptZero() const { return Ciphertext(GetHr()); }

template <bool audit>
Ciphertext Encryptor::EncryptImpl(const MPInt &m,
                                  std::string *audit_str) const {
  YACL_ENFORCE(m.CompareAbs(pk_.PlaintextBound()) < 0,
               "message number out of range, message={}, max (abs)={}", m,
               pk_.PlaintextBound());

  Ciphertext out;
  MPInt gm;
  if (m.IsNegative()) {
    pk_.m_space_->PowMod(*pk_.cgi_table_, m.Abs(), &gm);
  } else {
    pk_.m_space_->PowMod(*pk_.cg_table_, m, &gm);
  }

  auto hr = GetHr();
  pk_.m_space_->MulMod(hr, gm, &out.c_);
  if constexpr (audit) {
    YACL_ENFORCE(audit_str != nullptr);
    *audit_str = fmt::format(FMT_COMPILE("p:{},hr:{},c:{}"), m.ToHexString(),
                             hr.ToHexString(), out.c_.ToHexString());
  }
  return out;
}

Ciphertext Encryptor::Encrypt(const MPInt &m) const { return EncryptImpl(m); }

std::pair<Ciphertext, std::string> Encryptor::EncryptWithAudit(
    const MPInt &m) const {
  std::string audit_str;
  auto c = EncryptImpl<true>(m, &audit_str);
  return {c, audit_str};
}

}  // namespace heu::lib::algorithms::ou
