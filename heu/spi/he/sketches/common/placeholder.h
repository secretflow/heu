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

#include <map>
#include <string>

#include "heu/spi/he/sketches/common/keys.h"

namespace heu::spi {

template <HeKeyType key_type>
class NoKey : public spi::KeySketch<key_type> {
 public:
  std::map<std::string, std::string> ListParams() const override {
    YACL_THROW("There is no {} in the current setting, cannot list params",
               key_type);
  }

  std::string ToString() const override {
    return fmt::format("There is no {} in the current setting", key_type);
  }
};

class NoPk : public NoKey<HeKeyType::PublicKey> {};

class NoRlk : public NoKey<HeKeyType::RelinKeys> {};

class NoGlk : public NoKey<HeKeyType::GaloisKeys> {};

class NoBsk : public NoKey<HeKeyType::BootstrapKey> {};

}  // namespace heu::spi
