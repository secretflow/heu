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

#ifdef APPLY_LEICHI
#define ENABLE_LEICHI true
#else
#define ENABLE_LEICHI false
#endif

#if ENABLE_LEICHI == true

#include "heu/library/algorithms/leichi_paillier/vector_decryptor.h" 
#include "heu/library/algorithms/leichi_paillier/vector_encryptor.h"
#include "heu/library/algorithms/leichi_paillier/vector_evaluator.h"
#include "heu/library/algorithms/leichi_paillier/key_generator.h"
#include "heu/library/algorithms/leichi_paillier/public_key.h"
#include "heu/library/algorithms/leichi_paillier/secret_key.h"

#endif