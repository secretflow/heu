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

extern "C" {

#define CBITS 256
#define DCBITS 512

typedef struct {
  unsigned char n[DCBITS];          // n=p*q  ,pub key
  unsigned char n_squared[DCBITS];  // n^2
  unsigned char n_plusone[DCBITS];  // g=n+1,pub key
} h_paillier_pubkey_t;

typedef struct {
  unsigned char lambda[DCBITS];  // lambda(n), i.e., lcm(p-1,q-1) */
  unsigned char x[DCBITS];       //  prv key,u
} h_paillier_prvkey_t;

typedef struct {
  unsigned char m[DCBITS];  // cached to avoid recomputing */
} h_paillier_plaintext_t;

typedef struct {
  unsigned char c[DCBITS];  // cached to avoid recomputing */
} h_paillier_ciphertext_t;

typedef struct {
  unsigned char r[DCBITS];  // cached to avoid recomputing */
} h_paillier_random_t;

// api for gpu control
int gpu_setcard(int device_id);
int gpu_release_context(int device_id);

// gpu api for paillier
int gpu_paillier_enc(h_paillier_ciphertext_t *res, h_paillier_pubkey_t *pub,
                     h_paillier_plaintext_t *pt, h_paillier_random_t *rand,
                     unsigned int count);
int gpu_paillier_dec(h_paillier_plaintext_t *res, h_paillier_pubkey_t *pub,
                     h_paillier_prvkey_t *prv, h_paillier_ciphertext_t *ct,
                     unsigned int count);

int gpu_paillier_e_add(h_paillier_pubkey_t *pub, h_paillier_ciphertext_t *res,
                       h_paillier_ciphertext_t *ct0,
                       h_paillier_ciphertext_t *ct1, unsigned int count);
int gpu_paillier_e_add_const(h_paillier_pubkey_t *pub,
                             h_paillier_ciphertext_t *res,
                             h_paillier_ciphertext_t *ct,
                             h_paillier_plaintext_t *constant,
                             unsigned int count);
int gpu_paillier_e_mul_const(h_paillier_pubkey_t *pub,
                             h_paillier_ciphertext_t *res,
                             h_paillier_ciphertext_t *ct,
                             h_paillier_plaintext_t *constant,
                             unsigned int count);
int gpu_paillier_e_inverse(h_paillier_pubkey_t *pub,
                           h_paillier_ciphertext_t *res,
                           h_paillier_ciphertext_t *ct, unsigned int count);
int gpu_paillier_keygen(unsigned int modulus, h_paillier_pubkey_t *pub,
                        h_paillier_ciphertext_t *prv, h_paillier_random_t *rand,
                        unsigned int count);
int gpu_paillier_compare(h_paillier_plaintext_t *prv, unsigned int *rand,
                         unsigned int count);

int gpu_paillier_sub_ct(h_paillier_pubkey_t *pub, h_paillier_ciphertext_t *res,
                        h_paillier_ciphertext_t *ct0,
                        h_paillier_ciphertext_t *ct1, unsigned int count);
int gpu_paillier_sub_ctpt(h_paillier_pubkey_t *pub,
                          h_paillier_ciphertext_t *res,
                          h_paillier_ciphertext_t *ct,
                          h_paillier_plaintext_t *pt, unsigned int count);
int gpu_paillier_sub_ptct(h_paillier_pubkey_t *pub,
                          h_paillier_ciphertext_t *res,
                          h_paillier_plaintext_t *pt,
                          h_paillier_ciphertext_t *ct, unsigned int count);
}
