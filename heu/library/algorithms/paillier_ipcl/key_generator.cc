// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include "heu/library/algorithms/paillier_ipcl/key_generator.h"

#include "ipcl/bignum.h"
#include "ipcl/ipcl.hpp"

namespace heu::lib::algorithms::paillier_ipcl {

void KeyGenerator::Generate(int key_size, SecretKey* sk, PublicKey* pk) {
  ipcl::KeyPair key_pair;
  bool enable_DJN = true;  // enable DJN scheme by default

  key_pair = ipcl::generateKeypair(key_size, enable_DJN);
  pk->Init(key_pair.pub_key);
  sk->Init(key_pair.priv_key);
}
}  // namespace heu::lib::algorithms::paillier_ipcl
