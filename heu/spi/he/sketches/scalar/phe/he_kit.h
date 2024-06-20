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

#include "heu/spi/he/he_configs.h"
#include "heu/spi/he/sketches/common/he_kit.h"
#include "heu/spi/he/sketches/common/placeholder.h"
#include "heu/spi/he/sketches/scalar/phe/scaled_batch_encoder.h"
#include "heu/spi/he/sketches/scalar/phe/scaled_plain_encoder.h"

namespace heu::spi {

template <typename PlaintextT, typename SecretKeyT, typename PublicKeyT,
          typename RelinKeyT = NoRlk, typename GaloisKeyT = NoGlk,
          typename BootstrapKeyT = NoBsk>
class PheHeKitSketch : public HeKitSketch<SecretKeyT, PublicKeyT, RelinKeyT,
                                          GaloisKeyT, BootstrapKeyT> {
 public:
  virtual size_t MaxPlaintextBits() const = 0;

  FeatureSet GetFeatureSet() const override { return FeatureSet::AdditivePHE; }

 protected:
  std::shared_ptr<spi::Encoder> CreateEncoder(
      const spi::SpiArgs &args) const override {
    auto em = args.GetOrDefault(ArgEncodingMethod, "plain");
    if (em == "plain") {
      return std::make_shared<ScaledPlainEncoder<PlaintextT>>(
          args.GetOrDefault(ArgScale, 1e6));
    } else if (em == "batch") {
      return std::make_shared<ScaledBatchEncoder<PlaintextT>>(
          args.GetOrDefault(ArgScale, 1e6), MaxPlaintextBits(),
          args.GetOrDefault(ArgPadding, 32));
    } else {
      YACL_THROW("Unsupported encoding method {}", em);
    }
  }
};

}  // namespace heu::spi
