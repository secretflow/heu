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

// Author (Wen-jie Lu)
#pragma once

#include <memory>

#include "heu/experimental/gemini-rlwe/lwe_types.h"
#include "heu/experimental/gemini-rlwe/modswitch_helper.h"

namespace heu::expt::rlwe {

class LWEDecryptor {
 public:
  explicit LWEDecryptor(const LWESecretKey &sk,
                        const seal::SEALContext &context,
                        std::shared_ptr<ModulusSwitchHelper> ms_helper);

  ~LWEDecryptor();

  LWEDecryptor &operator=(const LWEDecryptor &) = delete;
  LWEDecryptor(const LWEDecryptor &) = delete;
  LWEDecryptor(LWEDecryptor &&) = delete;

  void Decrypt(const LWECt &ciphertext, uint32_t *out) const;

  void Decrypt(const LWECt &ciphertext, uint64_t *out) const;

  void Decrypt(const LWECt &ciphertext, uint128_t *out) const;

 protected:
  template <typename T>
  void DoDecrypt(const LWECt &ciphertext, T *out) const;

 private:
  LWESecretKey sk_;
  seal::SEALContext context_;
  std::shared_ptr<ModulusSwitchHelper> ms_helper_;
};

}  // namespace heu::expt::rlwe
