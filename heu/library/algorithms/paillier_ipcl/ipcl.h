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

#ifndef ENABLE_IPCL

#ifdef __x86_64__
#define ENABLE_IPCL true
#else
// IPCL do not support MAC(ARM) architecture
#define ENABLE_IPCL false
#endif

#endif

#if ENABLE_IPCL == true

#include "heu/library/algorithms/paillier_ipcl/ciphertext.h"
#include "heu/library/algorithms/paillier_ipcl/key_generator.h"
#include "heu/library/algorithms/paillier_ipcl/plaintext.h"
#include "heu/library/algorithms/paillier_ipcl/public_key.h"
#include "heu/library/algorithms/paillier_ipcl/secret_key.h"
#include "heu/library/algorithms/paillier_ipcl/vector_decryptor.h"
#include "heu/library/algorithms/paillier_ipcl/vector_encryptor.h"
#include "heu/library/algorithms/paillier_ipcl/vector_evaluator.h"

#endif
