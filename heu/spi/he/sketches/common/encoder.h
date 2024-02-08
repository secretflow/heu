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

#include <cstdint>
#include <string_view>

#include "heu/spi/he/encoder.h"

namespace heu::lib::spi {

template <typename PlaintextT>
class EncoderSketch : public Encoder {
 public:
  virtual PlaintextT FromStringT(std::string_view pt_str) const = 0;

  int64_t GetCleartextCount(const Item &plaintexts) const override {
    return plaintexts.Size<PlaintextT>() * SlotCount();
  }

 private:
  Item FromString(std::string_view plaintext) const override {
    return {FromStringT(plaintext), ContentType::Plaintext};
  }
};

}  // namespace heu::lib::spi
