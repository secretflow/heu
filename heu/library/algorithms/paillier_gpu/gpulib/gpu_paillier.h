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

// #define DEBUG

#include <cuda.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include "include/cgbn/cgbn.h"

template <uint32_t tpi, uint32_t bits, uint32_t window_bits>
class paillier_params_t {
 public:
  // parameters used by the CGBN context
  static const uint32_t TPB = 0;           // get TPB from blockDim.x
  static const uint32_t MAX_ROTATION = 4;  // good default value
  static const uint32_t SHM_LIMIT = 0;     // no shared mem available
  static const bool CONSTANT_TIME =
      false;  // constant time implementations aren't available yet

  // parameters used locally in the application
  static const uint32_t TPI = tpi;                  // threads per instance
  static const uint32_t BITS = bits;                // instance size
  static const uint32_t DBITS = bits;               // instance size
  static const uint32_t WINDOW_BITS = window_bits;  // window size
};

// typedef paillier_params_t<16, 2048, 5> params;
typedef paillier_params_t<16, 4096, 5> params;

typedef struct {
  // int bits;//2048

  // cgbn_mem_t<params::DBITS> n;// public modulus n = p q
  // cgbn_mem_t<params::DBITS> n_squared;// cached to avoid recomputing,it's n^2
  // cgbn_mem_t<params::DBITS> n_plusone;// cached to avoid recomputing,it's g
  cgbn_mem_t<4096> n;          // public modulus n = p q
  cgbn_mem_t<4096> n_squared;  // cached to avoid recomputing,it's n^2
  cgbn_mem_t<4096> n_plusone;  // cached to avoid recomputing,it's g
} gpu_paillier_pubkey_t;

typedef struct {
  cgbn_mem_t<params::DBITS> lambda;  // lambda(n), i.e., lcm(p-1,q-1)
  cgbn_mem_t<params::DBITS> x;       // cached to avoid recomputing
} gpu_paillier_prvkey_t;

typedef struct {
  cgbn_mem_t<params::DBITS> c;  // x of the output point
} gpu_paillier_ciphertext_t;

typedef struct {
  cgbn_mem_t<params::DBITS> m;  // x of the output point
} gpu_paillier_plaintext_t;

typedef struct {
  cgbn_mem_t<params::DBITS> x;  // x of the output point
} gpu_paillier_temp_x;

typedef struct {
  cgbn_mem_t<params::DBITS> m;  // x of the output point
} gpu_paillier_random_t;

template <class params>
class paillier_t {
 public:
  static const uint32_t window_bits = params::WINDOW_BITS;
  typedef cgbn_context_t<params::TPI, params> context_t;
  typedef cgbn_env_t<context_t, params::DBITS> env_t;
  typedef typename env_t::cgbn_t bn_t;
  typedef typename env_t::cgbn_wide_t bn_wide_t;
  typedef typename env_t::cgbn_local_t bn_local_t;
  context_t _context;
  env_t _env;
  int32_t _instance;

  __device__ __forceinline__ paillier_t(cgbn_monitor_t monitor,
                                        cgbn_error_report_t *report,
                                        int32_t instance)
      : _context(monitor, report, (uint32_t)instance),
        _env(_context),
        _instance(instance) {}

  __device__ __forceinline__ void fixed_window_powm_odd(bn_t &result,
                                                        const bn_t &x,
                                                        const bn_t &power,
                                                        const bn_t &modulus);
};
