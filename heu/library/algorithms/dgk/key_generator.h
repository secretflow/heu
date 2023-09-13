// Copyright 2023 zhangwfjh
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

#include "heu/library/algorithms/dgk/public_key.h"
#include "heu/library/algorithms/dgk/secret_key.h"

namespace heu::lib::algorithms::dgk {

class KeyGenerator {
 public:
  static void Generate(size_t key_size, SecretKey* sk, PublicKey* pk);
  static void Generate(SecretKey* sk, PublicKey* pk);

  constexpr static size_t l{16};   // recommended u size
  constexpr static size_t t{160};  // recommended v size; FIXME
};

}  // namespace heu::lib::algorithms::dgk
