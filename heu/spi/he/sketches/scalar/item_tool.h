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

#include "heu/spi/he/sketches/common/item_tool.h"
#include "heu/spi/he/sketches/scalar/helpful_macros.h"

namespace heu::spi {

template <typename PlaintextT, typename CiphertextT, typename SecretKeyT,
          typename PublicKeyT = NoPk, typename RelinKeyT = NoRlk,
          typename GaloisKeyT = NoGlk, typename BootstrapKeyT = NoBsk>
class ItemToolScalarSketch
    : public ItemToolSketch<PlaintextT, CiphertextT, SecretKeyT, PublicKeyT,
                            RelinKeyT, GaloisKeyT, BootstrapKeyT> {
 public:
  virtual PlaintextT Clone(const PlaintextT &pt) const = 0;
  virtual CiphertextT Clone(const CiphertextT &ct) const = 0;

 private:
  Item Clone(const Item &item) const override {
    switch (item.GetContentType()) {
      case ContentType::Plaintext:
        CallUnaryFunc(Clone, PlaintextT, item);
      case ContentType::Ciphertext:
        CallUnaryFunc(Clone, CiphertextT, item);
      default:
        // If you really want to clone a key, please create a GitHub issue
        YACL_THROW("Clone a {} is not supported.", item.GetContentType());
    }
  }
};

}  // namespace heu::spi
