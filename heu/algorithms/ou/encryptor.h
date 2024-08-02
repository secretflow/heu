// Copyright 2024 Ant Group Co., Ltd.
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

#pragma once

#include "heu/algorithms/ou/base.h"
#include "heu/spi/he/sketches/scalar/phe/encryptor.h"

namespace heu::algos::ou {

class Encryptor : public spi::PheEncryptorScalarSketch<Plaintext, Ciphertext> {
 public:
  explicit Encryptor(const std::shared_ptr<PublicKey> &pk,
                     bool enable_cache = false);

  [[nodiscard]] Ciphertext EncryptZeroT() const override;

  [[nodiscard]] Ciphertext Encrypt(const Plaintext &m) const override;
  void Encrypt(const Plaintext &m, Ciphertext *out) const override;

  void EncryptWithAudit(const Plaintext &m, Ciphertext *ct_out,
                        std::string *audit_out) const override;

  MPInt GetHr() const;

  void SetEnableCache(bool enable_cache) { enable_cache_ = enable_cache; }

 private:
  template <bool audit = false>
  Ciphertext EncryptImpl(const MPInt &m,
                         std::string *audit_str = nullptr) const;

  std::shared_ptr<MPInt> GetHrUsingCache() const;

  std::shared_ptr<PublicKey> pk_;

  bool enable_cache_;
  size_t random_bits_;

  mutable std::mutex hr_mutex_;
  mutable std::shared_ptr<MPInt> cache_r_;
  mutable std::shared_ptr<MPInt> cache_hr_;  // h^(cache_r_)
};

}  // namespace heu::algos::ou
