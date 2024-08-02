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

#include "heu/algorithms/paillier_zahlen/base.h"
#include "heu/spi/he/sketches/scalar/phe/he_kit.h"

namespace heu::algos::paillier_z {

class HeKit : public spi::PheHeKitSketch<Plaintext, SecretKey, PublicKey> {
 public:
  std::string GetLibraryName() const override;
  spi::Schema GetSchema() const override;

  std::string ToString() const override;

  size_t MaxPlaintextBits() const override {
    return pk_->PlaintextBound().BitCount() - 1;
  }

  size_t Serialize(uint8_t *buf, size_t buf_len) const override;
  size_t Serialize(spi::HeKeyType key_type, uint8_t *buf,
                   size_t buf_len) const override;

  static std::unique_ptr<spi::HeKit> Create(spi::Schema schema,
                                            const spi::SpiArgs &args);
  static bool Check(spi::Schema schema, const spi::SpiArgs &);

 private:
  void InitOperators();

  void GenPkSk(size_t key_size);
};

}  // namespace heu::algos::paillier_z
