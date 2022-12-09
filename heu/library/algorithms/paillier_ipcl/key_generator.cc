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

#include "ipcl/bignum.h"
#include "ipcl/ipcl.hpp"
#include "heu/library/algorithms/paillier_ipcl/key_generator.h"

namespace heu::lib::algorithms::paillier_ipcl {

void KeyGenerator::Generate(int key_size, SecretKey* sk, PublicKey* pk) {
  ipcl::KeyPair key_pair;
  bool enable_DJN = true;  // enable DJN scheme by default

  key_pair = ipcl::generateKeypair(key_size, enable_DJN);
  pk->Init(key_pair.pub_key);
  sk->Init(key_pair.priv_key);
}
}  // namespace heu::lib::algorithms::paillier_ipcl
