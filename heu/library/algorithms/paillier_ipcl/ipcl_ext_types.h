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

#pragma once

#include "yacl/base/int128.h"

namespace heu::lib::algorithms::paillier_ipcl {
void ipcl_set_u8(Plaintext *a, uint8_t b);

int8_t ipcl_get_i8(const Plaintext *a);
#define ipcl_get_u8(a) ((uint8_t)ipcl_get_i8(a));

}