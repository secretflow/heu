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

#include "heu/library/algorithms/paillier_gpu/gpulib/error.h"
#include "heu/library/algorithms/paillier_gpu/gpulib/gpu_paillier.h"
#include "heu/library/algorithms/paillier_gpu/gpulib/gpupaillier.h"

template <class params>
__device__ __forceinline__ void paillier_t<params>::fixed_window_powm_odd(
    bn_t &result, const bn_t &x, const bn_t &power, const bn_t &modulus) {
  bn_t t;
  bn_local_t window[1 << window_bits];
  int32_t index, position, offset;
  uint32_t np0;

  // conmpute x^power mod modulus, using the fixed window algorithm
  // requires:  x<modulus,  modulus is odd
  // compute x^0 (in Montgomery space, this is just 2^BITS - modulus)
  cgbn_negate(_env, t, modulus);
  cgbn_store(_env, window + 0, t);

  // convert x into Montgomery space, store into window table
  np0 = cgbn_bn2mont(_env, result, x, modulus);
  cgbn_store(_env, window + 1, result);
  cgbn_set(_env, t, result);

// compute x^2, x^3, ... x^(2^window_bits-1), store into window table
#pragma nounroll
  for (index = 2; index < (1 << window_bits); index++) {
    cgbn_mont_mul(_env, result, result, t, modulus, np0);
    cgbn_store(_env, window + index, result);
  }

  // find leading high bit
  position = params::BITS - cgbn_clz(_env, power);

  // break the exponent into chunks, each window_bits in length
  // load the most significant non-zero exponent chunk
  offset = position % window_bits;
  if (offset == 0)
    position = position - window_bits;
  else
    position = position - offset;
  index = cgbn_extract_bits_ui32(_env, power, position, window_bits);
  cgbn_load(_env, result, window + index);

  // process the remaining exponent chunks
  while (position > 0) {
// square the result window_bits times
#pragma nounroll
    for (int sqr_count = 0; sqr_count < window_bits; sqr_count++)
      cgbn_mont_sqr(_env, result, result, modulus, np0);

    // multiply by next exponent chunk
    position = position - window_bits;
    index = cgbn_extract_bits_ui32(_env, power, position, window_bits);
    cgbn_load(_env, t, window + index);
    cgbn_mont_mul(_env, result, result, t, modulus, np0);
  }

  // we've processed the exponent now, convert back to normal space
  cgbn_mont2bn(_env, result, result, modulus, np0);
}

// Sum the encrypted values by multiplying the ciphertexts
template <class params>
__global__ void kernel_paillier_enc(cgbn_error_report_t *report,
                                    gpu_paillier_ciphertext_t *gpu_res,
                                    gpu_paillier_pubkey_t *gpu_pub,
                                    gpu_paillier_plaintext_t *gpu_pt,
                                    gpu_paillier_random_t *rand,
                                    uint32_t count) {
  // decode an instance number from the blockIdx and threadIdx
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  // 4096bit variables
  paillier_t<params> po(cgbn_report_monitor, report, i);
  typename paillier_t<params>::bn_t r1, r2, g, x, p, m, n;
  typename paillier_t<params>::bn_wide_t r;

  cgbn_load(po._env, g, &(gpu_pub->n_plusone));
  cgbn_load(po._env, m, &(gpu_pt[i].m));
  cgbn_load(po._env, n, &(gpu_pub->n_squared));

  // Fake code:paillier.fixed_window_powm_odd(gpu_res[i].c, gpu_pub->n_plusone,
  // gpu_pt[i].m, gpu_pub->n_squared);
  po.fixed_window_powm_odd(r1, g, m, n);

  cgbn_load(po._env, x, &(rand[i].m));
  cgbn_load(po._env, p, &(gpu_pub->n));

  // Fake code:paillier.fixed_window_powm_odd(gpu_x.x, rand[i].m, gpu_pub->n,
  // gpu_pub->n_squared);
  po.fixed_window_powm_odd(r2, x, p, n);
  // cgbn_modular_power(po._env,r2,x,p,n); //the x should less than n

  // Fake code:paillier.mul(&(gpu_res[i].c), &(gpu_res[i].c), &(gpu_x.x));
  cgbn_mul_wide(po._env, r, r1, r2);  // the r is 8192 bit,r=r1*r2;

  // Fake code:paillier.mod(&(gpu_res[i].c), &(gpu_pub->n_squared));
  cgbn_rem_wide(po._env, r1, r,
                n);  // back to 4096 bit for next mod ,r1=r%m ,the high CGBN of
                     // r is less than the denominator

  cgbn_store(po._env, &(gpu_res[i].c), r1);
  return;
}

template <class params>
__global__ void kernel_paillier_dec(cgbn_error_report_t *report,
                                    gpu_paillier_plaintext_t *gpu_res,
                                    gpu_paillier_pubkey_t *gpu_pub,
                                    gpu_paillier_prvkey_t *gpu_prv,
                                    gpu_paillier_ciphertext_t *gpu_ct,
                                    uint32_t count) {
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  paillier_t<params> po(cgbn_report_monitor, report, i);
  typename paillier_t<params>::bn_t r, c, l, n, p, x;
  typename paillier_t<params>::bn_wide_t dr;

  cgbn_load(po._env, c, &(gpu_ct[i].c));
  cgbn_load(po._env, l, &(gpu_prv->lambda));
  cgbn_load(po._env, x, &(gpu_prv->x));
  cgbn_load(po._env, n, &(gpu_pub->n_squared));
  cgbn_load(po._env, p, &(gpu_pub->n));

  // Fake code:paillier.fixed_window_powm_odd(gpu_res[i].m, gpu_ct[i].c,
  // gpu_prv[i].lambda, gpu_pub[i].n_squared);
  po.fixed_window_powm_odd(r, c, l, n);
  // Fake code:paillier._env.sub_ui32(gpu_res[i].m, gpu_res[i].m, 1);
  po._env.sub_ui32(r, r, 1);
  // Fake code:paillier.div(gpu_res[i].m, gpu_res[i].m, gpu_pub->n);
  cgbn_div(po._env, r, r, p);
  // Fake code:paillier.mul(gpu_res[i].m, gpu_res[i].m, gpu_prv->x);
  cgbn_mul_wide(po._env, dr, r, x);  // 8192bits,should be fixed
  // Fake code:paillier.mod(gpu_res[i].m, gpu_pub->n);
  cgbn_rem_wide(po._env, r, dr, p);  // back to 4096,the high CGBN of num is
                                     // less than the denominator, denom.
  cgbn_store(po._env, &(gpu_res[i].m), r);
  return;
}

// Sum the encrypted values by multiplying the ciphertexts
template <class params>
__global__ void kernel_paillier_e_add(cgbn_error_report_t *report,
                                      gpu_paillier_ciphertext_t *gpu_res,
                                      gpu_paillier_pubkey_t *gpu_pub,
                                      gpu_paillier_ciphertext_t *gpu_ct0,
                                      gpu_paillier_ciphertext_t *gpu_ct1,
                                      uint32_t count) {
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  paillier_t<params> po(cgbn_report_monitor, report, i);

  typename paillier_t<params>::bn_t r, c0, c1, n;
  typename paillier_t<params>::bn_wide_t dr;
  cgbn_load(po._env, c0, &(gpu_ct0[i].c));
  cgbn_load(po._env, c1, &(gpu_ct1[i].c));
  cgbn_load(po._env, n, &(gpu_pub->n_squared));
  // paillier.d_mul(gpu_res[i].c, gpu_ct0[i].c, gpu_ct1[i].c);
  cgbn_mul_wide(po._env, dr, c0, c1);  // dr=c0*c1,  dr is 8192bits
  // paillier.d_mod(gpu_res[i].c, gpu_pub->n_squared);
  cgbn_rem_wide(po._env, r, dr, n);  // back to 4096
  cgbn_store(po._env, &(gpu_res[i].c), r);
  return;
}

template <class params>
__global__ void kernel_paillier_e_sub(cgbn_error_report_t *report,
                                      gpu_paillier_ciphertext_t *gpu_res,
                                      gpu_paillier_pubkey_t *gpu_pub,
                                      gpu_paillier_ciphertext_t *gpu_ct0,
                                      gpu_paillier_ciphertext_t *gpu_ct1,
                                      uint32_t count) {
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  paillier_t<params> po(cgbn_report_monitor, report, i);

  typename paillier_t<params>::bn_t r, c0, c1, n;
  typename paillier_t<params>::bn_wide_t dr;
  cgbn_load(po._env, c0, &(gpu_ct0[i].c));
  cgbn_load(po._env, c1, &(gpu_ct1[i].c));
  cgbn_load(po._env, n, &(gpu_pub->n_squared));

  cgbn_modular_inverse(po._env, r, c1, n);  // r=inv(c1)

  cgbn_mul_wide(po._env, dr, c0, r);  // dr=c0*r,  dr is 8192bits
  cgbn_rem_wide(po._env, r, dr, n);   // back to 4096
  cgbn_store(po._env, &(gpu_res[i].c), r);
  return;
}

template <class params>
__global__ void kernel_paillier_e_sub_ctpt(cgbn_error_report_t *report,
                                           gpu_paillier_ciphertext_t *gpu_res,
                                           gpu_paillier_pubkey_t *gpu_pub,
                                           gpu_paillier_ciphertext_t *gpu_ct,
                                           gpu_paillier_plaintext_t *gpu_pt,
                                           uint32_t count) {
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  paillier_t<params> po(cgbn_report_monitor, report, i);
  typename paillier_t<params>::bn_t r, c, m, n, g, ri, ro;
  typename paillier_t<params>::bn_wide_t dr;
  cgbn_load(po._env, c, &(gpu_ct[i].c));
  cgbn_load(po._env, m, &(gpu_pt[i].m));
  cgbn_load(po._env, n, &(gpu_pub->n_squared));
  cgbn_load(po._env, g, &(gpu_pub->n_plusone));

  po.fixed_window_powm_odd(r, g, m, n);

  cgbn_modular_inverse(po._env, ri, r, n);  // ri=inv(r)

  cgbn_mul_wide(po._env, dr, c, ri);  // dr=c*ri,  dr is 8192bits

  cgbn_rem_wide(po._env, r, dr, n);  // back to 4096
  cgbn_store(po._env, &(gpu_res[i].c), r);

  return;
}

template <class params>
__global__ void kernel_paillier_e_sub_ptct(cgbn_error_report_t *report,
                                           gpu_paillier_ciphertext_t *gpu_res,
                                           gpu_paillier_pubkey_t *gpu_pub,
                                           gpu_paillier_plaintext_t *gpu_pt,
                                           gpu_paillier_ciphertext_t *gpu_ct,
                                           uint32_t count) {
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  paillier_t<params> po(cgbn_report_monitor, report, i);
  typename paillier_t<params>::bn_t r, c, m, n, g, ri, rm;
  typename paillier_t<params>::bn_wide_t dr;
  cgbn_load(po._env, c, &(gpu_ct[i].c));
  cgbn_load(po._env, m, &(gpu_pt[i].m));
  cgbn_load(po._env, n, &(gpu_pub->n_squared));
  cgbn_load(po._env, g, &(gpu_pub->n_plusone));

  po.fixed_window_powm_odd(r, g, m, n);  // r=g^m mod n;

  cgbn_modular_inverse(po._env, ri, c, n);  // ri=inv(c)

  cgbn_mul_wide(po._env, dr, r, ri);  // dr=r*ri,  dr is 8192bits
  cgbn_rem_wide(po._env, r, dr, n);   // back to 4096
  cgbn_store(po._env, &(gpu_res[i].c), r);
  return;
}

// inv
template <class params>
__global__ void kernel_paillier_inv(cgbn_error_report_t *report,
                                    gpu_paillier_ciphertext_t *gpu_res,
                                    gpu_paillier_pubkey_t *gpu_pub,
                                    gpu_paillier_ciphertext_t *gpu_ctx,
                                    uint32_t count) {
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  paillier_t<params> po(cgbn_report_monitor, report, i);
  typename paillier_t<params>::bn_t r, c, n;
  // typename paillier_t<params>::bn_wide_t  dr;
  cgbn_load(po._env, c, &(gpu_ctx[i].c));
  cgbn_load(po._env, n, &(gpu_pub->n_squared));

  cgbn_modular_inverse(po._env, r, c, n);

  cgbn_store(po._env, &(gpu_res[i].c), r);
  return;
}

// inv inplace , it can not work, because the memory is not managed by the GPU
template <class params>
__global__ void kernel_paillier_inv_inplace(cgbn_error_report_t *report,
                                            gpu_paillier_pubkey_t *gpu_pub,
                                            gpu_paillier_ciphertext_t *gpu_ctx,
                                            uint32_t count) {
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  paillier_t<params> po(cgbn_report_monitor, report, i);
  typename paillier_t<params>::bn_t r, c, n;
  cgbn_load(po._env, c, &(gpu_ctx[i].c));
  cgbn_load(po._env, n, &(gpu_pub->n_squared));

  cgbn_modular_inverse(po._env, r, c, n);

  cgbn_store(po._env, &(gpu_ctx[i].c), r);  // replace the inpute
  return;
}

template <class params>
__global__ void kernel_paillier_e_add_const(cgbn_error_report_t *report,
                                            gpu_paillier_ciphertext_t *gpu_res,
                                            gpu_paillier_pubkey_t *gpu_pub,
                                            gpu_paillier_ciphertext_t *gpu_ct,
                                            gpu_paillier_plaintext_t *gpu_con,
                                            uint32_t count) {
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  paillier_t<params> po(cgbn_report_monitor, report, i);
  typename paillier_t<params>::bn_t r, c, n, g, t;
  typename paillier_t<params>::bn_wide_t dr;

  cgbn_load(po._env, c, &(gpu_ct[i].c));
  cgbn_load(po._env, n, &(gpu_pub->n_squared));
  cgbn_load(po._env, g, &(gpu_pub->n_plusone));
  cgbn_load(po._env, t, &(gpu_con[i].m));

  // Fake code: po.d_fixed_window_powm_odd(gpu_res[i].c, gpu_pub->n_plusone,
  // gpu_con[i], gpu_pub->n_squared);
  po.fixed_window_powm_odd(r, g, t, n);
  // Fake code: po.d_mul(gpu_res[i].c, gpu_ct[i].c, gpu_res[i].c);
  cgbn_mul_wide(po._env, dr, c, r);  // dr=c0*c1,  dr is 8192bits
  // Fake code: po.d_mod(gpu_res[i].c,gpu_pub.n_squared);
  cgbn_rem_wide(po._env, r, dr, n);  // back to 4096
  cgbn_store(po._env, &(gpu_res[i].c), r);
  return;
}

template <class params>
__global__ void kernel_paillier_e_mul_const(cgbn_error_report_t *report,
                                            gpu_paillier_ciphertext_t *gpu_res,
                                            gpu_paillier_pubkey_t *gpu_pub,
                                            gpu_paillier_ciphertext_t *gpu_ct,
                                            gpu_paillier_plaintext_t *gpu_con,
                                            uint32_t count) {
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  paillier_t<params> po(cgbn_report_monitor, report, i);
  typename paillier_t<params>::bn_t r, c, n, t;
  cgbn_load(po._env, c, &(gpu_ct[i].c));
  cgbn_load(po._env, n, &(gpu_pub->n_squared));
  cgbn_load(po._env, t, &(gpu_con[i].m));
  // Fake code:paillier.d_fixed_window_powm_odd(gpu_res[i].c, gpu_ct[i].c,
  // gpu_con[i].m, gpu_pub->n_squared);
  po.fixed_window_powm_odd(r, c, t, n);
  cgbn_store(po._env, &(gpu_res[i].c), r);
  return;
}

template <class params>
__global__ void kernel_paillier_compare(cgbn_error_report_t *report,
                                        gpu_paillier_plaintext_t *gpu_plain,
                                        uint32_t *gpu_res, uint32_t count) {
  int32_t i;
  i = (blockIdx.x * blockDim.x + threadIdx.x) / params::TPI;
  if (i >= count) return;

  int32_t j = -1;
  paillier_t<params> po(cgbn_report_monitor, report, i);
  typename paillier_t<params>::bn_t r;
  cgbn_load(po._env, r, &(gpu_plain[i].m));
  j = cgbn_compare_ui32(
      po._env, r, gpu_res[i]);  // compare the gpu result and the cpu result
  if (j != 0) printf("instance %d error: %u \n", i, gpu_res[i]);
  return;
  return;
}

void cudainit() {
  int count;
  cudaGetDeviceCount(&count);
  cudaError_t error_t = cudaSetDevice(0);
  if (error_t != cudaSuccess) printf("cuda error\n");
  error_t = cudaDeviceSetCacheConfig(cudaFuncCachePreferL1);
  if (error_t != cudaSuccess) printf("cuda error\n");
}

//*********************************************gpu
// api*****************************************
int gpu_paillier_enc_bk(h_paillier_ciphertext_t *res, h_paillier_pubkey_t *pub,
                        h_paillier_plaintext_t *pt, h_paillier_random_t *rand,
                        unsigned int count) {
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;

  unsigned int ps, BPG;
  BPG = 256;
  ps = TPB * BPG;  // kernel parallel ,256 means blocks per Grid

  unsigned int rem, sm_num, sm_count, sm_count_tail, loop, i = 0, j = 0;
  sm_num = 3;  // 3 streams is enough
  if (count < 3) {
    sm_num = 1;
  }
  sm_count = count / sm_num;  // sm_count may be bigger than ps
  sm_count_tail =
      count -
      sm_count * sm_num;  // it is very important ,the count number should be
                          // the multiples of 3, if not it will left 1，2。
  // sm_count_malloc=sm_count+sm_count_tail;//+2 for the left data,it's depends
  loop = sm_count /
         ps;  // loop could be 0, loops for each stream,every time is ps.
  if (sm_num == 1) {
    loop = 0;
  }

  cudainit();
  cudaStream_t stream[sm_num];
  // create stream
  for (i = 0; i < sm_num; i++) {
    cudaStreamCreate(&(stream[i]));
  }

  // malloc for each stream
  gpu_paillier_ciphertext_t *gpu_result[sm_num];
  gpu_paillier_pubkey_t *gpu_pub[sm_num];
  gpu_paillier_plaintext_t *gpu_pt[sm_num];
  gpu_paillier_random_t *gpu_random[sm_num];
  cgbn_error_report_t *report[sm_num];
  for (i = 0; i < sm_num; i++) {
    CUDA_CHECK(cudaMalloc((void **)&gpu_result[i],
                          sizeof(gpu_paillier_ciphertext_t) * ps));
    CUDA_CHECK(cudaMalloc((void **)&gpu_pub[i], sizeof(gpu_paillier_pubkey_t)));
    CUDA_CHECK(
        cudaMalloc((void **)&gpu_pt[i], sizeof(gpu_paillier_plaintext_t) * ps));
    CUDA_CHECK(cudaMalloc((void **)&gpu_random[i],
                          sizeof(gpu_paillier_random_t) * ps));
    CUDA_CHECK(cgbn_error_report_alloc(&report[i]));
  }

  if (loop == 0) {
    rem = sm_count;
  } else {
    rem = sm_count - loop * ps;  // each stream has rem, except count is < 3.
  }

  printf("sm_count:%d, sm_count_tail:%d,loop:%d,sm_Num:%d,rem:%d,ps:%d\n",
         sm_count, sm_count_tail, loop, sm_num, rem, ps);
  for (i = 0; i < loop; i++)  // all it ps,the wave
  {
    for (j = 0; j < sm_num; j++) {
      cudaMemcpyAsync((void *)(gpu_pt[j]),
                      (pt + sm_num * i * ps * sizeof(gpu_paillier_plaintext_t) +
                       j * ps * sizeof(gpu_paillier_plaintext_t)),
                      sizeof(gpu_paillier_plaintext_t) * ps,
                      cudaMemcpyHostToDevice, stream[j]);
      cudaMemcpyAsync((void *)gpu_pub[j], pub, sizeof(gpu_paillier_pubkey_t),
                      cudaMemcpyHostToDevice, stream[j]);
      cudaMemcpyAsync((void *)(gpu_random[j]),
                      (rand + sm_num * i * ps * sizeof(gpu_paillier_random_t) +
                       j * ps * sizeof(gpu_paillier_random_t)),
                      sizeof(gpu_paillier_random_t) * ps,
                      cudaMemcpyHostToDevice, stream[j]);
      // kernel_paillier_enc<params>  <<< BPG, TPB,0,stream[j]  >>> (report[i],
      // gpu_result[j], gpu_pub[j], gpu_pt[j], gpu_random[j], ps);
      kernel_paillier_enc<params><<<(ps + IPB - 1) / IPB, TPB, 0, stream[j]>>>(
          report[i], gpu_result[j], gpu_pub[j], gpu_pt[j], gpu_random[j], ps);

      cudaMemcpyAsync(
          (void *)(res + sm_num * i * ps * sizeof(gpu_paillier_ciphertext_t) +
                   j * ps * sizeof(gpu_paillier_ciphertext_t)),
          (gpu_result[j]), sizeof(gpu_paillier_ciphertext_t) * ps,
          cudaMemcpyDeviceToHost, stream[j]);
      printf("loop!=0: %d,stream number:%d\n", i, j);
    }
  }

  i = loop;
  for (j = 0; j < sm_num; j++)  // the rem ,works well
  {
    cudaMemcpyAsync((void *)(gpu_pt[j]),
                    (pt + sm_num * i * ps * sizeof(gpu_paillier_plaintext_t) +
                     j * rem * sizeof(gpu_paillier_plaintext_t)),
                    sizeof(gpu_paillier_plaintext_t) * rem,
                    cudaMemcpyHostToDevice, stream[j]);
    cudaMemcpyAsync((void *)gpu_pub[j], pub, sizeof(gpu_paillier_pubkey_t),
                    cudaMemcpyHostToDevice, stream[j]);
    cudaMemcpyAsync((void *)(gpu_random[j]),
                    (rand + sm_num * i * ps * sizeof(gpu_paillier_random_t) +
                     j * rem * sizeof(gpu_paillier_random_t)),
                    sizeof(gpu_paillier_random_t) * rem, cudaMemcpyHostToDevice,
                    stream[j]);
    // kernel_paillier_enc<params>  <<< BPG, TPB,0,stream[j] >>> (report[i],
    // gpu_result[j], gpu_pub[j], gpu_pt[j], gpu_random[j], rem);
    kernel_paillier_enc<params><<<(rem + IPB - 1) / IPB, TPB, 0, stream[j]>>>(
        report[i], gpu_result[j], gpu_pub[j], gpu_pt[j], gpu_random[j], rem);

    cudaMemcpyAsync(
        (void *)(res + sm_num * i * ps * sizeof(gpu_paillier_ciphertext_t) +
                 j * rem * sizeof(gpu_paillier_ciphertext_t)),
        (gpu_result[j]), sizeof(gpu_paillier_ciphertext_t) * rem,
        cudaMemcpyDeviceToHost, stream[j]);
    printf("loop=i: %d,stream number:%d\n", i, j);
  }
  j = 0;
  if (sm_count_tail > 0) {
    cudaMemcpyAsync((void *)(gpu_pt[j]),
                    (pt + sm_num * i * ps * sizeof(gpu_paillier_plaintext_t) +
                     sm_num * rem * sizeof(gpu_paillier_plaintext_t)),
                    sizeof(gpu_paillier_plaintext_t) * sm_count_tail,
                    cudaMemcpyHostToDevice, stream[j]);
    cudaMemcpyAsync((void *)gpu_pub[j], pub, sizeof(gpu_paillier_pubkey_t),
                    cudaMemcpyHostToDevice, stream[j]);
    cudaMemcpyAsync((void *)(gpu_random[j]),
                    (rand + sm_num * i * ps * sizeof(gpu_paillier_random_t) +
                     sm_num * rem * sizeof(gpu_paillier_random_t)),
                    sizeof(gpu_paillier_random_t) * sm_count_tail,
                    cudaMemcpyHostToDevice, stream[j]);
    // kernel_paillier_enc<params> <<< BPG, TPB,0,stream[j] >>> (report[i],
    // gpu_result[j], gpu_pub[j], gpu_pt[j], gpu_random[j], sm_count_tail);
    kernel_paillier_enc<params>
        <<<(sm_count_tail + IPB - 1) / IPB, TPB, 0, stream[j]>>>(
            report[i], gpu_result[j], gpu_pub[j], gpu_pt[j], gpu_random[j],
            sm_count_tail);

    cudaMemcpyAsync(
        (void *)(res + sm_num * i * ps * sizeof(gpu_paillier_ciphertext_t) +
                 sm_num * rem * sizeof(gpu_paillier_ciphertext_t)),
        (gpu_result[j]), sizeof(gpu_paillier_ciphertext_t) * sm_count_tail,
        cudaMemcpyDeviceToHost, stream[j]);
    printf("sm_count_tail ,stream number:%d\n", j);
  }
  for (j = 0; j < sm_num; j++) {
    cudaStreamSynchronize(stream[j]);
  }
  for (int j = 0; j < sm_num; j++) {
    cudaStreamDestroy(stream[j]);
  }
  CUDA_LAST_CHECK();
  for (i = 0; i < sm_num; i++) {
    CUDA_CHECK(cudaFree(gpu_pt[i]));      // data_in_gpu
    CUDA_CHECK(cudaFree(gpu_pub[i]));     // pub
    CUDA_CHECK(cudaFree(gpu_random[i]));  // random data
    CUDA_CHECK(cudaFree(gpu_result[i]));  // cm
    CGBN_CHECK(report[i]);
    CUDA_CHECK(cgbn_error_report_free(report[i]));
  }

  return 0;
}

int gpu_paillier_enc(h_paillier_ciphertext_t *res, h_paillier_pubkey_t *pub,
                     h_paillier_plaintext_t *pt, h_paillier_random_t *rand,
                     unsigned int count) {
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;

  gpu_paillier_ciphertext_t *gpu_result;
  gpu_paillier_pubkey_t *gpu_pub;
  gpu_paillier_plaintext_t *gpu_pt;
  gpu_paillier_random_t *gpu_random;
  cgbn_error_report_t *report;

  int32_t BPG = 256;

  CUDA_CHECK(cudaSetDevice(0));
  CUDA_CHECK(cudaMalloc((void **)&gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_pub, sizeof(gpu_paillier_pubkey_t)));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_pt, sizeof(gpu_paillier_plaintext_t) * count));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_random, sizeof(gpu_paillier_random_t) * count));
  CUDA_CHECK(cgbn_error_report_alloc(&report));

  CUDA_CHECK(cudaMemcpy(gpu_pub, pub, sizeof(gpu_paillier_pubkey_t),
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_pt, (gpu_paillier_plaintext_t *)pt,
                        sizeof(gpu_paillier_plaintext_t) * count,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_random, (gpu_paillier_random_t *)rand,
                        sizeof(gpu_paillier_random_t) * count,
                        cudaMemcpyHostToDevice));

  // kernel_paillier_enc<params> << <(count + IPB - 1) / IPB, TPB >> > (report,
  // gpu_result, gpu_pub, gpu_pt, gpu_random, count);
  unsigned int ps, rep, rem, i = 0;
  ps = TPB * BPG;  // kernel parallel
  if (ps < count) {
    rep = count / ps;
    for (i = 0; i < rep; i++) {
      kernel_paillier_enc<params><<<(ps + IPB - 1) / IPB, TPB>>>(
          report, &gpu_result[i * ps], gpu_pub, &gpu_pt[i * ps],
          &gpu_random[i * ps], ps);
    }
    rem = count - ps * rep;
    kernel_paillier_enc<params><<<(rem + IPB - 1) / IPB, TPB>>>(
        report, &gpu_result[i * ps], gpu_pub, &gpu_pt[i * ps],
        &gpu_random[i * ps], rem);
  } else {
    kernel_paillier_enc<params><<<(count + IPB - 1) / IPB, TPB>>>(
        report, gpu_result, gpu_pub, gpu_pt, gpu_random, count);
  }

  CUDA_CHECK(cudaDeviceSynchronize());
  CUDA_LAST_CHECK();
  CGBN_CHECK(report);
  CUDA_CHECK(cudaMemcpy(res, gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaFree(gpu_result));
  CUDA_CHECK(cudaFree(gpu_pub));
  CUDA_CHECK(cudaFree(gpu_pt));
  CUDA_CHECK(cudaFree(gpu_random));
  CUDA_CHECK(cgbn_error_report_free(report));
  return 0;
}

int gpu_paillier_dec(h_paillier_plaintext_t *res, h_paillier_pubkey_t *pub,
                     h_paillier_prvkey_t *prv, h_paillier_ciphertext_t *ct,
                     unsigned int count) {
  // unsigned int TPI, TPB, IPB;
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;
  gpu_paillier_plaintext_t *gpu_result;
  gpu_paillier_pubkey_t *gpu_pub;
  gpu_paillier_prvkey_t *gpu_prv;
  gpu_paillier_ciphertext_t *gpu_ct;

  cgbn_error_report_t *report;

  CUDA_CHECK(cudaMalloc((void **)&gpu_result,
                        sizeof(gpu_paillier_plaintext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_pub, sizeof(gpu_paillier_pubkey_t)));
  CUDA_CHECK(cudaMalloc((void **)&gpu_prv, sizeof(gpu_paillier_prvkey_t)));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_ct, sizeof(gpu_paillier_ciphertext_t) * count));

  CUDA_CHECK(cgbn_error_report_alloc(&report));
  CUDA_CHECK(cudaMemcpy(gpu_pub, pub, sizeof(gpu_paillier_pubkey_t),
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_prv, prv, sizeof(gpu_paillier_prvkey_t),
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_ct, ct, sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));

  kernel_paillier_dec<params><<<(count + IPB - 1) / IPB, TPB>>>(
      report, gpu_result, gpu_pub, gpu_prv, gpu_ct, count);

  CUDA_CHECK(cudaDeviceSynchronize());
  CUDA_LAST_CHECK();
  CGBN_CHECK(report);
  CUDA_CHECK(cudaMemcpy(res, gpu_result,
                        sizeof(gpu_paillier_plaintext_t) * count,
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaFree(gpu_result));
  CUDA_CHECK(cudaFree(gpu_pub));
  CUDA_CHECK(cudaFree(gpu_prv));
  CUDA_CHECK(cudaFree(gpu_ct));
  CUDA_CHECK(cgbn_error_report_free(report));
  return 0;
}

int gpu_paillier_e_add(h_paillier_pubkey_t *pub, h_paillier_ciphertext_t *res,
                       h_paillier_ciphertext_t *ct0,
                       h_paillier_ciphertext_t *ct1, unsigned int count) {
  // unsigned int TPI, TPB, IPB;
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;
  gpu_paillier_ciphertext_t *gpu_result;
  gpu_paillier_pubkey_t *gpu_pub;
  gpu_paillier_ciphertext_t *gpu_ct0;
  gpu_paillier_ciphertext_t *gpu_ct1;

  cgbn_error_report_t *report;

  CUDA_CHECK(cudaMalloc((void **)&gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_pub, sizeof(gpu_paillier_pubkey_t) * 1));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_ct0, sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_ct1, sizeof(gpu_paillier_ciphertext_t) * count));

  CUDA_CHECK(cgbn_error_report_alloc(&report));
  CUDA_CHECK(cudaMemcpy(gpu_pub, pub, sizeof(gpu_paillier_pubkey_t) * 1,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_ct0, ct0, sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_ct1, ct1, sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));

  kernel_paillier_e_add<params><<<(count + IPB - 1) / IPB, TPB>>>(
      report, gpu_result, gpu_pub, gpu_ct0, gpu_ct1, count);

  CUDA_CHECK(cudaDeviceSynchronize());
  CUDA_LAST_CHECK();
  CGBN_CHECK(report);
  CUDA_CHECK(cudaMemcpy(res, gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaFree(gpu_result));
  CUDA_CHECK(cudaFree(gpu_pub));
  CUDA_CHECK(cudaFree(gpu_ct0));
  CUDA_CHECK(cudaFree(gpu_ct1));
  CUDA_CHECK(cgbn_error_report_free(report));
  return 0;
}

int gpu_paillier_e_inverse(h_paillier_pubkey_t *pub,
                           h_paillier_ciphertext_t *res,
                           h_paillier_ciphertext_t *ct, unsigned int count) {
  // unsigned int TPI, TPB, IPB;
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;
  gpu_paillier_ciphertext_t *gpu_result;
  gpu_paillier_pubkey_t *gpu_pub;
  gpu_paillier_ciphertext_t *gpu_ct;

  cgbn_error_report_t *report;

  CUDA_CHECK(cudaMalloc((void **)&gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_pub, sizeof(gpu_paillier_pubkey_t) * 1));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_ct, sizeof(gpu_paillier_ciphertext_t) * count));

  CUDA_CHECK(cgbn_error_report_alloc(&report));
  CUDA_CHECK(cudaMemcpy(gpu_pub, pub, sizeof(gpu_paillier_pubkey_t) * 1,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_ct, ct, sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));

  kernel_paillier_inv<params><<<(count + IPB - 1) / IPB, TPB>>>(
      report, gpu_result, gpu_pub, gpu_ct, count);

  CUDA_CHECK(cudaDeviceSynchronize());
  CUDA_LAST_CHECK();
  CGBN_CHECK(report);
  CUDA_CHECK(cudaMemcpy(res, gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaFree(gpu_result));
  CUDA_CHECK(cudaFree(gpu_pub));
  CUDA_CHECK(cudaFree(gpu_ct));
  CUDA_CHECK(cgbn_error_report_free(report));
  return 0;
}

int gpu_paillier_e_add_const(h_paillier_pubkey_t *pub,
                             h_paillier_ciphertext_t *res,
                             h_paillier_ciphertext_t *ct,
                             h_paillier_plaintext_t *constant,
                             unsigned int count) {
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;

  gpu_paillier_pubkey_t *gpu_pub;
  gpu_paillier_ciphertext_t *gpu_result;
  gpu_paillier_ciphertext_t *gpu_ct;
  gpu_paillier_plaintext_t *gpu_constant;

  cgbn_error_report_t *report;

  gpu_constant = (gpu_paillier_plaintext_t *)constant;

  CUDA_CHECK(cudaMalloc((void **)&gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_pub, sizeof(gpu_paillier_pubkey_t)));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_ct, sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_constant,
                        sizeof(gpu_paillier_plaintext_t) * count));

  CUDA_CHECK(cgbn_error_report_alloc(&report));

  CUDA_CHECK(cudaMemcpy(gpu_pub, pub, sizeof(gpu_paillier_pubkey_t),
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_ct, ct, sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_constant, constant,
                        sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));

  kernel_paillier_e_add_const<params><<<(count + IPB - 1) / IPB, TPB>>>(
      report, gpu_result, gpu_pub, gpu_ct, gpu_constant, count);

  CUDA_CHECK(cudaDeviceSynchronize());
  CUDA_LAST_CHECK();
  CGBN_CHECK(report);
  CUDA_CHECK(cudaMemcpy(res, gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaFree(gpu_result));
  CUDA_CHECK(cudaFree(gpu_pub));
  CUDA_CHECK(cudaFree(gpu_ct));
  CUDA_CHECK(cudaFree(gpu_constant));
  CUDA_CHECK(cgbn_error_report_free(report));
  return 0;
}

int gpu_paillier_sub_ct(h_paillier_pubkey_t *pub, h_paillier_ciphertext_t *res,
                        h_paillier_ciphertext_t *ct0,
                        h_paillier_ciphertext_t *ct1, unsigned int count) {
  // unsigned int TPI, TPB, IPB;
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;
  gpu_paillier_ciphertext_t *gpu_result;
  gpu_paillier_pubkey_t *gpu_pub;
  gpu_paillier_ciphertext_t *gpu_ct0;
  gpu_paillier_ciphertext_t *gpu_ct1;

  cgbn_error_report_t *report;

  CUDA_CHECK(cudaMalloc((void **)&gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_pub, sizeof(gpu_paillier_pubkey_t) * 1));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_ct0, sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_ct1, sizeof(gpu_paillier_ciphertext_t) * count));

  CUDA_CHECK(cgbn_error_report_alloc(&report));
  CUDA_CHECK(cudaMemcpy(gpu_pub, pub, sizeof(gpu_paillier_pubkey_t) * 1,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_ct0, ct0, sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_ct1, ct1, sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));

  kernel_paillier_e_sub<params><<<(count + IPB - 1) / IPB, TPB>>>(
      report, gpu_result, gpu_pub, gpu_ct0, gpu_ct1, count);

  CUDA_CHECK(cudaDeviceSynchronize());
  CUDA_LAST_CHECK();
  CGBN_CHECK(report);
  CUDA_CHECK(cudaMemcpy(res, gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaFree(gpu_result));
  CUDA_CHECK(cudaFree(gpu_pub));
  CUDA_CHECK(cudaFree(gpu_ct0));
  CUDA_CHECK(cudaFree(gpu_ct1));
  CUDA_CHECK(cgbn_error_report_free(report));
  return 0;
}

int gpu_paillier_sub_ctpt(h_paillier_pubkey_t *pub,
                          h_paillier_ciphertext_t *res,
                          h_paillier_ciphertext_t *ct,
                          h_paillier_plaintext_t *pt, unsigned int count) {
  // unsigned int TPI, TPB, IPB;
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;
  gpu_paillier_ciphertext_t *gpu_result;
  gpu_paillier_pubkey_t *gpu_pub;
  gpu_paillier_ciphertext_t *gpu_ct;
  gpu_paillier_plaintext_t *gpu_pt;

  cgbn_error_report_t *report;

  CUDA_CHECK(cudaMalloc((void **)&gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_pub, sizeof(gpu_paillier_pubkey_t) * 1));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_ct, sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_pt, sizeof(gpu_paillier_plaintext_t) * count));

  CUDA_CHECK(cgbn_error_report_alloc(&report));
  CUDA_CHECK(cudaMemcpy(gpu_pub, pub, sizeof(gpu_paillier_pubkey_t) * 1,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_ct, ct, sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_pt, pt, sizeof(gpu_paillier_plaintext_t) * count,
                        cudaMemcpyHostToDevice));

  kernel_paillier_e_sub_ctpt<params><<<(count + IPB - 1) / IPB, TPB>>>(
      report, gpu_result, gpu_pub, gpu_ct, gpu_pt, count);

  CUDA_CHECK(cudaDeviceSynchronize());
  CUDA_LAST_CHECK();
  CGBN_CHECK(report);
  CUDA_CHECK(cudaMemcpy(res, gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaFree(gpu_result));
  CUDA_CHECK(cudaFree(gpu_pub));
  CUDA_CHECK(cudaFree(gpu_ct));
  CUDA_CHECK(cudaFree(gpu_pt));
  CUDA_CHECK(cgbn_error_report_free(report));
  return 0;
}

int gpu_paillier_sub_ptct(h_paillier_pubkey_t *pub,
                          h_paillier_ciphertext_t *res,
                          h_paillier_plaintext_t *pt,
                          h_paillier_ciphertext_t *ct, unsigned int count) {
  // unsigned int TPI, TPB, IPB;
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;
  gpu_paillier_ciphertext_t *gpu_result;
  gpu_paillier_pubkey_t *gpu_pub;
  gpu_paillier_ciphertext_t *gpu_ct;
  gpu_paillier_plaintext_t *gpu_pt;

  cgbn_error_report_t *report;

  CUDA_CHECK(cudaMalloc((void **)&gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_pub, sizeof(gpu_paillier_pubkey_t) * 1));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_ct, sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_pt, sizeof(gpu_paillier_plaintext_t) * count));

  CUDA_CHECK(cgbn_error_report_alloc(&report));
  CUDA_CHECK(cudaMemcpy(gpu_pub, pub, sizeof(gpu_paillier_pubkey_t) * 1,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_ct, ct, sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_pt, pt, sizeof(gpu_paillier_plaintext_t) * count,
                        cudaMemcpyHostToDevice));

  kernel_paillier_e_sub_ptct<params><<<(count + IPB - 1) / IPB, TPB>>>(
      report, gpu_result, gpu_pub, gpu_pt, gpu_ct, count);

  CUDA_CHECK(cudaDeviceSynchronize());
  CUDA_LAST_CHECK();
  CGBN_CHECK(report);
  CUDA_CHECK(cudaMemcpy(res, gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaFree(gpu_result));
  CUDA_CHECK(cudaFree(gpu_pub));
  CUDA_CHECK(cudaFree(gpu_ct));
  CUDA_CHECK(cudaFree(gpu_pt));
  CUDA_CHECK(cgbn_error_report_free(report));
  return 0;
}

int gpu_paillier_e_mul_const(h_paillier_pubkey_t *pub,
                             h_paillier_ciphertext_t *res,
                             h_paillier_ciphertext_t *ct,
                             h_paillier_plaintext_t *constant,
                             unsigned int count) {
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;
  gpu_paillier_ciphertext_t *gpu_result;
  gpu_paillier_pubkey_t *gpu_pub;
  gpu_paillier_ciphertext_t *gpu_ct;
  gpu_paillier_plaintext_t *gpu_constant;

  cgbn_error_report_t *report;

  gpu_constant = (gpu_paillier_plaintext_t *)constant;
  CUDA_CHECK(cudaMalloc((void **)&gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_pub, sizeof(gpu_paillier_pubkey_t)));
  CUDA_CHECK(
      cudaMalloc((void **)&gpu_ct, sizeof(gpu_paillier_ciphertext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_constant,
                        sizeof(gpu_paillier_plaintext_t) * count));

  CUDA_CHECK(cgbn_error_report_alloc(&report));
  CUDA_CHECK(cudaMemcpy(gpu_pub, (gpu_paillier_pubkey_t *)pub,
                        sizeof(gpu_paillier_pubkey_t), cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_ct, (gpu_paillier_ciphertext_t *)ct,
                        sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_constant, constant,
                        sizeof(gpu_paillier_plaintext_t) * count,
                        cudaMemcpyHostToDevice));

  kernel_paillier_e_mul_const<params><<<(count + IPB - 1) / IPB, TPB>>>(
      report, gpu_result, gpu_pub, gpu_ct, gpu_constant, count);

  CUDA_CHECK(cudaDeviceSynchronize());
  CUDA_LAST_CHECK();
  CGBN_CHECK(report);
  CUDA_CHECK(cudaMemcpy(res, gpu_result,
                        sizeof(gpu_paillier_ciphertext_t) * count,
                        cudaMemcpyDeviceToHost));
  CUDA_CHECK(cudaFree(gpu_result));
  CUDA_CHECK(cudaFree(gpu_pub));
  CUDA_CHECK(cudaFree(gpu_ct));
  CUDA_CHECK(cudaFree(gpu_constant));
  CUDA_CHECK(cgbn_error_report_free(report));
  return 0;
}

int gpu_paillier_compare(h_paillier_plaintext_t *plain, unsigned int *res,
                         unsigned int count) {
  int32_t TPB = (params::TPB == 0)
                    ? 64
                    : params::TPB;  // default threads per block to 128
  int32_t TPI = params::TPI, IPB = TPB / TPI;  // IPB is instances per block

  gpu_paillier_plaintext_t *gpu_plain;
  unsigned int *gpu_res;

  cgbn_error_report_t *report;

  CUDA_CHECK(cudaMalloc((void **)&gpu_plain,
                        sizeof(gpu_paillier_plaintext_t) * count));
  CUDA_CHECK(cudaMalloc((void **)&gpu_res, sizeof(unsigned int) * count));

  CUDA_CHECK(cgbn_error_report_alloc(&report));
  CUDA_CHECK(cudaMemcpy(gpu_plain, plain,
                        sizeof(gpu_paillier_plaintext_t) * count,
                        cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(gpu_res, res, sizeof(unsigned int) * count,
                        cudaMemcpyHostToDevice));

  kernel_paillier_compare<params>
      <<<(count + IPB - 1) / IPB, TPB>>>(report, gpu_plain, gpu_res, count);

  CUDA_CHECK(cudaDeviceSynchronize());
  CUDA_LAST_CHECK();
  CGBN_CHECK(report);
  CUDA_CHECK(cudaFree(gpu_plain));
  CUDA_CHECK(cudaFree(gpu_res));
  CUDA_CHECK(cgbn_error_report_free(report));
  return 0;
}
