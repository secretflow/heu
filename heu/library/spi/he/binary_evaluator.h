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

#include "heu/library/spi/he/base.h"

namespace heu::lib::spi {

// Short int operations based on TFHE
// 基于 Bitwise FHE 封装得到的高级 integer 操作
class BinaryEvaluator {
 public:
  ~BinaryEvaluator() = default;

  // Bitwise operations.
  virtual Item ShiftL(const Item &x, uint32_t bits) const = 0;
  virtual void ShiftLInplace(Item *x, uint32_t bits) const = 0;

  virtual Item ShiftR(const Item &x, uint32_t bits) const = 0;
  virtual void ShiftRInplace(Item *x, uint32_t bits) const = 0;

  virtual Item RotateL(const Item &x, uint32_t bits) const = 0;
  virtual void RotateLInplace(Item *x, uint32_t bits) const = 0;

  virtual Item RotateR(const Item &x, uint32_t bits) const = 0;
  virtual void RotateRInplace(Item *x, uint32_t bits) const = 0;

  // Comparisons.
  virtual Item IsEqual(const Item &x, const Item &y) const = 0;
  virtual Item IsNotEqual(const Item &x, const Item &y) const = 0;
  virtual Item IsGreaterThan(const Item &x, const Item &y) const = 0;
  virtual Item IsGreaterEqual(const Item &x, const Item &y) const = 0;
  virtual Item IsLower(const Item &x, const Item &y) const = 0;
  virtual Item IsLowerEqual(const Item &x, const Item &y) const = 0;

  virtual Item Min(const Item &x) const = 0;
  virtual Item Min(const Item &x, const Item &y) const = 0;
  virtual Item Max(const Item &x) const = 0;
  virtual Item Max(const Item &x, const Item &y) const = 0;

  // other api: type cast support, programmable bootstrapping support
};

}  // namespace heu::lib::spi
