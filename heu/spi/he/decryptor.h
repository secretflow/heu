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

class Decryptor {
 public:
  virtual ~Decryptor() = default;

  // CT -> PT
  // CTs -> PTs
  virtual void Decrypt(const Item &ct, Item *out) const = 0;
  virtual Item Decrypt(const Item &ct) const = 0;
};

}  // namespace heu::spi
