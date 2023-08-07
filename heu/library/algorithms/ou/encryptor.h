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

#pragma once

#include <mutex>
#include <utility>

#include "heu/library/algorithms/ou/ciphertext.h"
#include "heu/library/algorithms/ou/public_key.h"

namespace heu::lib::algorithms::ou {

class Encryptor {
 public:
  explicit Encryptor(PublicKey pk, bool enable_cache = false);
  Encryptor(const Encryptor& from);

  Ciphertext EncryptZero() const;  // Get Enc(0)
  Ciphertext Encrypt(const MPInt& m) const;

  std::pair<Ciphertext, std::string> EncryptWithAudit(const MPInt& m) const;

  MPInt GetHr() const;

  void SetEnableCache(bool enable_cache) { enable_cache_ = enable_cache; }

 private:
  template <bool audit = false>
  Ciphertext EncryptImpl(const MPInt& m,
                         std::string* audit_str = nullptr) const;

  std::shared_ptr<MPInt> GetHrUsingCache() const;

  const PublicKey pk_;

  bool enable_cache_;
  size_t random_bits_;

  mutable std::mutex hr_mutex_;
  mutable std::shared_ptr<MPInt> cache_r_;
  mutable std::shared_ptr<MPInt> cache_hr_;  // h^(cache_r_)
};

}  // namespace heu::lib::algorithms::ou
