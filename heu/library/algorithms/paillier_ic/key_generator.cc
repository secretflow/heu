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

#include "heu/library/algorithms/paillier_ic/key_generator.h"

#include "heu/library/algorithms/paillier_zahlen/key_generator.h"

namespace heu::lib::algorithms::paillier_ic {

void KeyGenerator::Generate(size_t key_size, SecretKey *sk, PublicKey *pk) {
  paillier_z::PublicKey zpk;

  paillier_z::KeyGenerator::Generate(key_size, sk, &zpk);
  pk->n_ = zpk.n_;
  pk->h_s_ = zpk.h_s_;
  pk->Init();
}

void KeyGenerator::Generate(SecretKey *sk, PublicKey *pk) {
  Generate(2048, sk, pk);
}

}  // namespace heu::lib::algorithms::paillier_ic
