// Copyright 2023 Clustar Technology Co., Ltd.
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

#ifdef APPLY_CLUSTAR_FPGA
#define ENABLE_CLUSTAR_FPGA true
#else
#define ENABLE_CLUSTAR_FPGA false
#endif

#if ENABLE_CLUSTAR_FPGA == true

#include "heu/library/algorithms/paillier_clustar_fpga/ciphertext.h"
#include "heu/library/algorithms/paillier_clustar_fpga/key_generator.h"
#include "heu/library/algorithms/paillier_clustar_fpga/plaintext.h"
#include "heu/library/algorithms/paillier_clustar_fpga/public_key.h"
#include "heu/library/algorithms/paillier_clustar_fpga/secret_key.h"
#include "heu/library/algorithms/paillier_clustar_fpga/vector_decryptor.h"
#include "heu/library/algorithms/paillier_clustar_fpga/vector_encryptor.h"
#include "heu/library/algorithms/paillier_clustar_fpga/vector_evaluator.h"

#endif
