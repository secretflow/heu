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

#include "heu/spi/he/item.h"

namespace heu::spi {

// For single bit operations
class GateEvaluator {
 public:
  virtual ~GateEvaluator() = default;

  /*
   * Item 本质上在 C++ 之上构建了一套无类型系统，类似于
   * Python，任何类型都可以转换成 Item， 反之 Item 也可以变成任何实际类型。
   *
   * 一些缩写约定：
   *   PT => Plaintext
   *   CT => Ciphertext
   *   PTs => Plaintext Array
   *   CTs => Ciphertext Array
   */

  // CT = -CT
  // CTs = -CTS
  virtual Item Not(const Item &x) const = 0;
  virtual void NotInplace(Item *x) const = 0;

  // PT = PT & PT
  // CT = PT & CT
  // CT = CT & PT
  // CT = CT & CT
  // PTs = PTs & PT [Broadcast]
  // CTs = PTs & CT [Broadcast]
  // CTs = CTs & PT [Broadcast]
  // CTs = CTs & CT [Broadcast]
  // PTs = PT & PTs [Broadcast]
  // CTs = PT & CTs [Broadcast]
  // CTs = CT & PTs [Broadcast]
  // CTs = CT & CTs [Broadcast]
  // PTs = PTs & PTs
  // CTs = PTs & CTs
  // CTs = CTs & PTs
  // CTs = CTs & CTs
  // If Item is plaintext, then the real type must be bool or vector/span<bool>
  virtual Item And(const Item &x, const Item &y) const = 0;
  // CT &= PT
  // CT &= CT
  // CTs &= PT [Broadcast]
  // CTs &= CT [Broadcast]
  // CTs &= PTs
  // CTs &= CTs
  virtual void AndInplace(Item *x, const Item &y) const = 0;
  // AND gate with bootstrapping
  virtual Item BootAnd(const Item &x, const Item &y) const = 0;
  virtual void BootAndInplace(Item *x, const Item &y) const = 0;

  virtual Item Or(const Item &x, const Item &y) const = 0;
  virtual void OrInplace(Item *x, const Item &y) const = 0;
  virtual Item BootOr(const Item &x, const Item &y) const = 0;
  virtual void BootOrInplace(Item *x, const Item &y) const = 0;

  virtual Item Xor(const Item &x, const Item &y) const = 0;
  virtual void XorInplace(Item *x, const Item &y) const = 0;
  virtual Item BootXor(const Item &x, const Item &y) const = 0;
  virtual void BootXorInplace(Item *x, const Item &y) const = 0;

  virtual Item Nand(const Item &x, const Item &y) const = 0;
  virtual void NandInplace(Item *x, const Item &y) const = 0;
  virtual Item BootNand(const Item &x, const Item &y) const = 0;
  virtual void BootNandInplace(Item *x, const Item &y) const = 0;

  virtual Item Nor(const Item &x, const Item &y) const = 0;
  virtual void NorInplace(Item *x, const Item &y) const = 0;
  virtual Item BootNor(const Item &x, const Item &y) const = 0;
  virtual void BootNorInplace(Item *x, const Item &y) const = 0;

  virtual Item Xnor(const Item &x, const Item &y) const = 0;
  virtual void XnorInplace(Item *x, const Item &y) const = 0;
  virtual Item BootXnor(const Item &x, const Item &y) const = 0;
  virtual void BootXnorInplace(Item *x, const Item &y) const = 0;
};

}  // namespace heu::spi
