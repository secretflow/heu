// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "heu/library/algorithms/paillier_ipcl/public_key.h"
#include "heu/library/algorithms/paillier_ipcl/secret_key.h"

namespace heu::lib::algorithms::paillier_ipcl {

class KeyGenerator {
public:
  // Generate PHE key pair
  static void Generate(int key_size, SecretKey* sk, PublicKey* pk);
};

}  // namespace heu::lib::algorithms::paillier_ipcl
