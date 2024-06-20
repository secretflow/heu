// Copyright (C) 2021 Intel Corporation
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

#include "heu/library/algorithms/paillier_ipcl/public_key.h"
#include "heu/library/algorithms/paillier_ipcl/secret_key.h"

namespace heu::lib::algorithms::paillier_ipcl {

class KeyGenerator {
 public:
  // Generate PHE key pair
  static void Generate(int key_size, SecretKey *sk, PublicKey *pk);
  // Generate PHE key pair by default configs
  static void Generate(SecretKey *sk, PublicKey *pk);
};

}  // namespace heu::lib::algorithms::paillier_ipcl
