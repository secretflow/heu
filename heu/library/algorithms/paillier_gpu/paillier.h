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

#pragma once

// DJ paillier scheme, reference: https://www.brics.dk/DS/03/9/BRICS-DS-03-9.pdf

#ifndef ENABLE_GPAILLIER
#define ENABLE_GPAILLIER false
#endif

#if ENABLE_GPAILLIER == true
#include "heu/library/algorithms/paillier_gpu/ciphertext.h"
#include "heu/library/algorithms/paillier_gpu/decryptor.h"
#include "heu/library/algorithms/paillier_gpu/encryptor.h"
#include "heu/library/algorithms/paillier_gpu/evaluator.h"
#include "heu/library/algorithms/paillier_gpu/key_generator.h"
#include "heu/library/algorithms/paillier_gpu/public_key.h"
#include "heu/library/algorithms/paillier_gpu/secret_key.h"
#endif
