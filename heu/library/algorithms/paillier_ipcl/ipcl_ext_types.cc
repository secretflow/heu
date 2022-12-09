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

#include "ipcl_ext_types.h"

#define MP_SET_UNSIGNED(name, type)                                      \
  void name(mp_int *a, type b) {                                         \
    int i = 0;                                                           \
    while (b != 0u) {                                                    \
      a->dp[i++] = ((mp_digit)b & MP_MASK);                              \
      if (MP_SIZEOF_BITS(type) <= MP_DIGIT_BIT) {                        \
        break;                                                           \
      }                                                                  \
      b >>= ((MP_SIZEOF_BITS(type) <= MP_DIGIT_BIT) ? 0 : MP_DIGIT_BIT); \
    }                                                                    \
    a->used = i;                                                         \
    a->sign = MP_ZPOS;                                                   \
    MP_ZERO_DIGITS(a->dp + a->used, a->alloc - a->used);                 \
  }

#define MP_SET_SIGNED(name, uname, type, utype) \
  void name(mp_int *a, type b) {                \
    uname(a, (b < 0) ? -(utype)b : (utype)b);   \
    if (b < 0) {                                \
      a->sign = MP_NEG;                         \
    }                                           \
  }

MP_SET_UNSIGNED(mp_set_u8, uint8_t)
MP_SET_SIGNED(mp_set_i8, mp_set_u8, int8_t, uint8_t)