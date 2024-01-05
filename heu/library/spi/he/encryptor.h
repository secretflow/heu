// Copyright 2022 Ant Group Co., Ltd.
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

class Encryptor {
 public:
  // message is encoded plaintext or plaintext array
  // For all HE schema, plaintext is a custom type defined by underlying lib
  // For 1bit-boolean-FHE, plaintext can be bool or custom type
  virtual Item Encrypt(const Item &message) const = 0;
};

}  // namespace heu::lib::spi
