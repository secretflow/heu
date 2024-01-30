// Copyright 2023 Ant Group Co., Ltd.
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

#include "heu/spi/poly/poly_def.h"

namespace heu::lib::spi {

// Performs nega-cyclic forward and inverse number-theoretic transform (NTT)
// nega-cyclic means polynomial is mod by (X^N + 1)
class NttOperator {
 public:
  virtual ~NttOperator() = default;

  //=== (Batched) NTT Operations ===//
  virtual Polys Forward(const Polys &Polys_in) const = 0;
  virtual void ForwardInplace(Polys *Polys) const = 0;

  virtual Polys Inverse(const Polys &Polys_in) const = 0;
  virtual void InverseInplace(Polys *Polys) const = 0;
};

}  // namespace heu::lib::spi
