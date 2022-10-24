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

#include "tommath.h"
#include "yasl/base/buffer.h"

#include "heu/library/algorithms/util/endian.h"

namespace heu::lib::algorithms {

// Reference: https://eprint.iacr.org/2003/186.pdf
// libtommath style
void mp_ext_safe_prime_rand(mp_int *out, int t, int size);

void mp_ext_rand_bits(mp_int *out, int64_t bits);

// Convert num to bytes and output to buf
void mp_ext_to_bytes(const mp_int &num, unsigned char *buf, int64_t byte_len,
                     Endian endian = Endian::native);

}  // namespace heu::lib::algorithms
