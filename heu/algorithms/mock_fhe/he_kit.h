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

#include <memory>
#include <string>

#include "heu/algorithms/mock_fhe/base.h"
#include "heu/spi/he/encoder.h"
#include "heu/spi/he/sketches/common/he_kit.h"

namespace heu::algos::mock_fhe {

class HeKit : public spi::HeKitSketch<SecretKey, PublicKey, RelinKeys,
                                      GaloisKeys, BootstrapKey> {
 public:
  std::string GetLibraryName() const override;
  spi::Schema GetSchema() const override;
  spi::FeatureSet GetFeatureSet() const override;

  std::string ToString() const override;

  size_t Serialize(uint8_t *buf, size_t buf_len) const override;
  size_t Serialize(spi::HeKeyType key_type, uint8_t *buf,
                   size_t buf_len) const override;

  static std::unique_ptr<spi::HeKit> Create(spi::Schema schema,
                                            const spi::SpiArgs &args);
  static bool Check(spi::Schema schema, const spi::SpiArgs &);

 protected:
  std::shared_ptr<spi::Encoder> CreateEncoder(
      const yacl::SpiArgs &args) const override;

 private:
  void InitOperators();
  void Deserialize(yacl::ByteContainerView in);

  size_t poly_degree_;
  spi::Schema schema_;
  int64_t scale_;
};

}  // namespace heu::algos::mock_fhe
