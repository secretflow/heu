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

#include <cstddef>

#include "heu/spi/he/sketches/common/item_manipulator.h"
#include "heu/spi/he/sketches/scalar/helpful_macros.h"

namespace heu::lib::spi {

template <typename PlaintextT, typename CiphertextT, typename SecretKeyT,
          typename PublicKeyT = NoPk, typename RelinKeyT = NoRlk,
          typename GaloisKeyT = NoGlK, typename BootstrapKeyT = NoBsk>
class ItemManipulatorScalarSketch
    : public ItemManipulatorCommon<PlaintextT, CiphertextT, SecretKeyT,
                                   PublicKeyT, RelinKeyT, GaloisKeyT,
                                   BootstrapKeyT> {
  using Super =
      ItemManipulatorCommon<PlaintextT, CiphertextT, SecretKeyT, PublicKeyT,
                            RelinKeyT, GaloisKeyT, BootstrapKeyT>;

 public:
  using Super::Clone;
  virtual PlaintextT Clone(const PlaintextT& pt) const = 0;
  virtual CiphertextT Clone(const CiphertextT& ct) const = 0;

 private:
  Item Clone(const Item& item) const override {
    switch (item.GetContentType()) {
      case ContentType::Plaintext:
        CallUnaryFunc(Clone, PlaintextT, item);
      case ContentType::Ciphertext:
        CallUnaryFunc(Clone, CiphertextT, item);
      default:
        return Super::Clone(item);
    }
  }
};

}  // namespace heu::lib::spi
