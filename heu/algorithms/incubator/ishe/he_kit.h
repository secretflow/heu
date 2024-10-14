// Copyright 2024 CyberChangAn Group, Xidian University.
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

#include <string>

#include "heu/algorithms/incubator/ishe/base.h"
#include "heu/algorithms/incubator/ishe/decryptor.h"
#include "heu/algorithms/incubator/ishe/encryptor.h"
#include "heu/algorithms/incubator/ishe/evaluator.h"
#include "heu/spi/he/sketches/common/he_kit.h"
#include "heu/spi/he/sketches/scalar/phe/he_kit.h"

DECLARE_ARG_int64(k0);
DECLARE_ARG_int64(kr);
DECLARE_ARG_int64(kM);

namespace heu::algos::ishe {
class HeKit
    : public spi::PheHeKitSketch<Plaintext, SecretKey, PublicParameters> {
 public:
  HeKit() = default;
  [[nodiscard]] std::string GetLibraryName() const override;
  [[nodiscard]] spi::Schema GetSchema() const override;

  [[nodiscard]] std::string ToString() const override;

  [[nodiscard]] size_t MaxPlaintextBits() const override {
    return pk_->Maxsize();
  }

  size_t Serialize(uint8_t *buf, size_t buf_len) const override;
  size_t Serialize(spi::HeKeyType key_type, uint8_t *buf,
                   size_t buf_len) const override;

  void GenPkSk(int64_t k_0, int64_t k_r, int64_t k_M);
  static std::unique_ptr<HeKit> CreateParams(spi::Schema schema, int64_t k_0,
                                             int64_t k_r, int64_t k_M);
  static std::unique_ptr<HeKit> Create(spi::Schema schema,
                                       const spi::SpiArgs &args);

  static bool Check(spi::Schema schema, const spi::SpiArgs &);

  std::shared_ptr<SecretKey> getSk() { return this->sk_; }

  std::shared_ptr<PublicParameters> getPk() { return this->pk_; }

 private:
  void InitOperators();
  void InitOnes(int64_t k_0, int64_t k_r, int64_t k_M, const MPInt &N,
                std::vector<MPInt> *ADDONES, std::vector<MPInt> *ONES,
                std::vector<MPInt> *NEGS);
};

}  // namespace heu::algos::ishe
