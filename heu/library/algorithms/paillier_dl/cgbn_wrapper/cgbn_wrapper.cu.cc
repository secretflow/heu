// Copyright 2023 Denglin Co., Ltd.
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
#include <random>
#include <climits>
#include <gmp.h>
#include "cgbn/cgbn.h"
#include "heu/library/algorithms/paillier_dl/cgbn_wrapper/cgbn_wrapper.h"
#include "heu/library/algorithms/paillier_dl/cgbn_wrapper/gpu_support.h"

// #define DEBUG

namespace heu::lib::algorithms::paillier_dl {

typedef cgbn_context_t<TPI>         context_t;
typedef cgbn_env_t<context_t, BITS> env_t;
typedef typename env_t::cgbn_t                bn_t;
typedef typename env_t::cgbn_local_t          bn_local_t;
typedef cgbn_mem_t<BITS> gpu_mpz; 

static __device__ void p_cgbn(char *name, cgbn_mem_t<BITS> *d) {
  printf("[%s]\n", name);
  for (int i=0; i<(sizeof(d->_limbs) + 3) / 4; i++) {
    printf("%08x ", d->_limbs[i]);
  }
  printf("\n");
}

static void buf_cal_used(uint64_t *buf, int size, int *used) {
  int count = 0;
  for (int i=0; i<size; i++) {
    if (buf[i] != 0) {
      count = i + 1;
    }
  }
  *used = count;
}

static void store2dev(dev_mem_t<BITS> *address, const MPInt &z) {
  auto buffer = z.ToMagBytes(Endian::little);
  if (buffer.size() > sizeof(address->_limbs)) {
    printf("%s:%d No enough memory, need: %d, real: %d\n", __FILE__, __LINE__, buffer.size(), sizeof(address->_limbs));
    abort();
  }
 
  CUDA_CHECK(cudaMemset(address->_limbs, 0, sizeof(address->_limbs)));
  CUDA_CHECK(cudaMemcpy(address->_limbs, buffer.data(), buffer.size(), cudaMemcpyHostToDevice));
}

static void store2dev(void *address, const PublicKey &pk) {
  CUDA_CHECK(cudaMemcpy(address, &pk, sizeof(PublicKey), cudaMemcpyHostToDevice));
}

static void store2dev(void *address, const SecretKey &sk) {
  CUDA_CHECK(cudaMemcpy(address, &sk, sizeof(SecretKey), cudaMemcpyHostToDevice));
}

static void store2host(MPInt *z, dev_mem_t<BITS> *address) {
  int32_t z_size = sizeof(address->_limbs);
  
  yacl::Buffer buffer(z_size);

  CUDA_CHECK(cudaMemcpy(buffer.data(), address->_limbs,  z_size, cudaMemcpyDeviceToHost));

  int used = 0;
  buf_cal_used((mp_digit *)buffer.data(), z_size / sizeof(mp_digit), &used);

  buffer.resize(used * sizeof(mp_digit));
  Endian endian = Endian::little;
  (*z).FromMagBytes(buffer, endian);
}

__device__ __forceinline__ void powmod(env_t &bn_env, env_t::cgbn_t &r, env_t::cgbn_t &a, env_t::cgbn_t &b, env_t::cgbn_t &c) {
  if(cgbn_compare(bn_env, a, b) >= 0) {
    cgbn_rem(bn_env, r, a, c);
  } 
  cgbn_modular_power(bn_env, r, r, b, c);
}

__device__  __forceinline__ void h_func(env_t &bn_env, env_t::cgbn_t &out, env_t::cgbn_t &g_t, env_t::cgbn_t &x_t, env_t::cgbn_t &xsquare_t) {
  env_t::cgbn_t  tmp, tmp2;
  cgbn_sub_ui32(bn_env, tmp, x_t, 1);
  powmod(bn_env, tmp2, g_t, tmp, xsquare_t);
  cgbn_sub_ui32(bn_env, tmp2, tmp2, 1);
  cgbn_div(bn_env, tmp2, tmp2, x_t);
  cgbn_modular_inverse(bn_env, out, tmp2, x_t);
}

__device__  __forceinline__ void l_func(env_t &bn_env, env_t::cgbn_t &out, env_t::cgbn_t &cipher_t, env_t::cgbn_t &x_t, env_t::cgbn_t &xsquare_t, env_t::cgbn_t &hx_t) {
  env_t::cgbn_t  tmp, tmp2, cipher_lt;
  cgbn_sub_ui32(bn_env, tmp2, x_t, 1);
  if(cgbn_compare(bn_env, cipher_t, xsquare_t) >= 0) {
    cgbn_rem(bn_env, cipher_lt, cipher_t, xsquare_t);
    cgbn_modular_power(bn_env, tmp, cipher_lt, tmp2, xsquare_t);
  } else {
    cgbn_modular_power(bn_env, tmp, cipher_t, tmp2, xsquare_t);
  }
  cgbn_sub_ui32(bn_env, tmp, tmp, 1);
  cgbn_div(bn_env, tmp, tmp, x_t);
  cgbn_mul(bn_env, tmp, tmp, hx_t);
  cgbn_rem(bn_env, tmp, tmp, x_t);
  cgbn_set(bn_env, out, tmp);
}

__global__ __noinline__ void raw_init_sk(SecretKey *priv_key, cgbn_error_report_t *report, int count) {
  int tid=(blockIdx.x*blockDim.x + threadIdx.x)/TPI;
  if(tid>=count)
    return;

  context_t      bn_context(cgbn_report_monitor, report, tid);
  env_t          bn_env(bn_context.env<env_t>());
  env_t::cgbn_t  tmp, g, p, q, hp, hq, psquare, qsquare, qinverse;
  cgbn_load(bn_env, g, (cgbn_mem_t<BITS> *)priv_key->dev_g_);
  cgbn_load(bn_env, p, (cgbn_mem_t<BITS> *)priv_key->dev_p_);
  cgbn_load(bn_env, q, (cgbn_mem_t<BITS> *)priv_key->dev_q_);

  cgbn_mul(bn_env, psquare, p, p);
  cgbn_store(bn_env, (cgbn_mem_t<BITS> *)priv_key->dev_psquare_, psquare);

  cgbn_mul(bn_env, qsquare, q, q);
  cgbn_store(bn_env, (cgbn_mem_t<BITS> *)priv_key->dev_qsquare_, qsquare);

  cgbn_modular_inverse(bn_env, qinverse, q, p);
  cgbn_store(bn_env, (cgbn_mem_t<BITS> *)priv_key->dev_q_inverse_, qinverse);

  h_func(bn_env, hp, g, p, psquare);
  cgbn_store(bn_env, (cgbn_mem_t<BITS> *)priv_key->dev_hp_, hp);

  h_func(bn_env, hq, g, q, qsquare);
  cgbn_store(bn_env, (cgbn_mem_t<BITS> *)priv_key->dev_hq_, hq);

#ifdef DEBUG
  if (blockIdx.x == 0 && threadIdx.x == 0) {
    p_cgbn("dev_g_", (cgbn_mem_t<BITS> *)priv_key->dev_g_);
    p_cgbn("dev_p_", (cgbn_mem_t<BITS> *)priv_key->dev_p_);
    p_cgbn("dev_q_", (cgbn_mem_t<BITS> *)priv_key->dev_q_);
    p_cgbn("dev_psquare_", (cgbn_mem_t<BITS> *)priv_key->dev_psquare_);
    p_cgbn("dev_qsquare_", (cgbn_mem_t<BITS> *)priv_key->dev_qsquare_);
    p_cgbn("dev_q_inverse_", (cgbn_mem_t<BITS> *)priv_key->dev_q_inverse_);
    p_cgbn("dev_hp_", (cgbn_mem_t<BITS> *)priv_key->dev_hp_);
    p_cgbn("dev_hq_", (cgbn_mem_t<BITS> *)priv_key->dev_hq_);
  }
#endif
}

void CGBNWrapper::InitSK(SecretKey *sk) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = 1;

  cgbn_error_report_t *report;

  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_init_sk<<<(count+IPB-1)/IPB, TPB>>>(sk->dev_sk_, report,  count); 
  CUDA_CHECK(cudaDeviceSynchronize());

  CGBN_CHECK(report);

  CUDA_CHECK(cgbn_error_report_free(report));
}

__global__ __noinline__ void raw_init_pk(PublicKey *pub_key, cgbn_error_report_t *report, int count) {
  int tid=(blockIdx.x*blockDim.x + threadIdx.x)/TPI;
  if(tid>=count)
    return;

  context_t      bn_context(cgbn_report_monitor, report, tid);
  env_t          bn_env(bn_context.env<env_t>());
  env_t::cgbn_t  tmp, n, g, nsquare, max_int;
  cgbn_load(bn_env, n, (cgbn_mem_t<BITS> *)pub_key->dev_n_);

  cgbn_add_ui32(bn_env, g, n, 1);
  cgbn_store(bn_env, (cgbn_mem_t<BITS> *)pub_key->dev_g_, g);

  cgbn_mul(bn_env, nsquare, n, n);
  cgbn_store(bn_env, (cgbn_mem_t<BITS> *)pub_key->dev_nsquare_, nsquare);

  cgbn_div_ui32(bn_env, max_int, n, 3);
  cgbn_sub_ui32(bn_env, max_int, max_int, 1);
  cgbn_store(bn_env, (cgbn_mem_t<BITS> *)pub_key->dev_max_int_, max_int);

#ifdef DEBUG
  if (blockIdx.x == 0 && threadIdx.x == 0) {
    p_cgbn("dev_g_", (cgbn_mem_t<BITS> *)pub_key->dev_g_);
    p_cgbn("dev_n_", (cgbn_mem_t<BITS> *)pub_key->dev_n_);
    p_cgbn("dev_nsquare_", (cgbn_mem_t<BITS> *)pub_key->dev_nsquare_);
    p_cgbn("dev_max_int_", (cgbn_mem_t<BITS> *)pub_key->dev_max_int_);
  }
#endif
}

void CGBNWrapper::InitPK(PublicKey *pk) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = 1;

  cgbn_error_report_t *report;

  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_init_pk<<<(count+IPB-1)/IPB, TPB>>>(pk->dev_pk_, report,  count); 
  CUDA_CHECK(cudaDeviceSynchronize());

  CGBN_CHECK(report);

  CUDA_CHECK(cgbn_error_report_free(report));
}

__global__ __noinline__ void raw_encrypt(PublicKey *pub_key, cgbn_error_report_t *report, gpu_mpz *plains, gpu_mpz *ciphers,  gpu_mpz *rs, int count) {
  int tid=(blockIdx.x*blockDim.x + threadIdx.x)/TPI;
  if(tid>=count)
    return;
  context_t      bn_context(cgbn_report_monitor, report, tid);  
  env_t          bn_env(bn_context.env<env_t>());                   
  env_t::cgbn_t  n, nsquare, plain,  tmp, max_int, neg_plain, neg_cipher, cipher, r;               
  cgbn_load(bn_env, n, (cgbn_mem_t<BITS> *)pub_key->dev_n_);      
  cgbn_load(bn_env, plain, plains + tid);      
  cgbn_load(bn_env, nsquare, (cgbn_mem_t<BITS> *)pub_key->dev_nsquare_);
  cgbn_load(bn_env, max_int, (cgbn_mem_t<BITS> *)pub_key->dev_max_int_);
  cgbn_load(bn_env, plain, plains + tid);
  cgbn_load(bn_env, r, rs);
  cgbn_sub(bn_env, tmp, n, max_int); 
  if(cgbn_compare(bn_env, plain, tmp) >= 0 &&  cgbn_compare(bn_env, plain, n) < 0) {
    // Very large plaintext, take a sneaky shortcut using inverses
    cgbn_sub(bn_env, neg_plain, n, plain);
    cgbn_mul(bn_env, neg_cipher, n, neg_plain);
    cgbn_add_ui32(bn_env, neg_cipher, neg_cipher, 1);
    cgbn_rem(bn_env, neg_cipher, neg_cipher, nsquare);
    cgbn_modular_inverse(bn_env, cipher, neg_cipher, nsquare);
  } else {
    cgbn_mul(bn_env, cipher, n, plain);
    cgbn_add_ui32(bn_env, cipher, cipher, 1);
    cgbn_rem(bn_env, cipher, cipher, nsquare);
  }
  cgbn_modular_power(bn_env, tmp, r, n, nsquare); 
  cgbn_mul(bn_env, tmp, cipher, tmp); 
  cgbn_rem(bn_env, r, tmp, nsquare);
  cgbn_store(bn_env, ciphers + tid, r);   // store r into sum

#ifdef DEBUG
  if (blockIdx.x == 0 && threadIdx.x == 0) {
    for (int i=0; i<count; i++) {
      p_cgbn("[encrypt] dev_plains", plains + i);
      p_cgbn("[encrypt] dev_ciphers", ciphers + i);
    }
    p_cgbn("dev_g_", (cgbn_mem_t<BITS> *)pub_key->dev_g_);
    p_cgbn("dev_n_", (cgbn_mem_t<BITS> *)pub_key->dev_n_);
    p_cgbn("dev_nsquare_", (cgbn_mem_t<BITS> *)pub_key->dev_nsquare_);
    p_cgbn("dev_max_int_", (cgbn_mem_t<BITS> *)pub_key->dev_max_int_);
  }
#endif
}

void CGBNWrapper::Encrypt(const std::vector<Plaintext>& pts, const PublicKey& pk, std::vector<Ciphertext>* cts) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int32_t count = pts.size();

  cgbn_error_report_t *report;
  cgbn_mem_t<BITS> *dev_plains;
  cgbn_mem_t<BITS> *dev_ciphers;
  cgbn_mem_t<BITS> *dev_r;

  CUDA_CHECK(cudaMalloc((void **)&dev_plains, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_ciphers, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_r, sizeof(cgbn_mem_t<BITS>)));

  CUDA_CHECK(cudaMemset(dev_plains->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_ciphers->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));

  for (int i=0; i<count; i++) {
    store2dev((dev_mem_t<BITS> *)(dev_plains + i), pts[i]); 
  }
  MPInt r;
  MPInt::RandomLtN(pk.max_int_, &r);
  store2dev((dev_mem_t<BITS> *)dev_r, r); 

  CUDA_CHECK(cgbn_error_report_alloc(&report));


  raw_encrypt<<<(count+IPB-1)/IPB, TPB>>>(pk.dev_pk_, report,  dev_plains, dev_ciphers, dev_r, count); 
  CUDA_CHECK(cudaDeviceSynchronize());

  for (int i=0; i<count; i++) {
    store2host(&(*cts)[i].c_, (dev_mem_t<BITS> *)(dev_ciphers + i));
  }

  CGBN_CHECK(report);

  CUDA_CHECK(cgbn_error_report_free(report));
  CUDA_CHECK(cudaFree(dev_plains));
  CUDA_CHECK(cudaFree(dev_ciphers));
  CUDA_CHECK(cudaFree(dev_r));
}


__global__ void raw_decrypt(SecretKey *priv_key, dev_mem_t<BITS> *pk_n, cgbn_error_report_t *report, gpu_mpz *plains, gpu_mpz *ciphers, int count) {
  int tid=(blockIdx.x*blockDim.x + threadIdx.x)/TPI;
  if(tid>=count)
    return;

  context_t      bn_context(cgbn_report_monitor, report, tid);
  env_t          bn_env(bn_context.env<env_t>());
  env_t::cgbn_t  mp, mq, tmp, q_inverse, n, p, q, hp, hq, psquare, qsquare, cipher;
  cgbn_load(bn_env, cipher, ciphers + tid);
  cgbn_load(bn_env, q_inverse, (cgbn_mem_t<BITS> *)priv_key->dev_q_inverse_);
  cgbn_load(bn_env, n, (cgbn_mem_t<BITS> *)pk_n);
  cgbn_load(bn_env, p, (cgbn_mem_t<BITS> *)priv_key->dev_p_);
  cgbn_load(bn_env, q, (cgbn_mem_t<BITS> *)priv_key->dev_q_);
  cgbn_load(bn_env, hp, (cgbn_mem_t<BITS> *)priv_key->dev_hp_);
  cgbn_load(bn_env, hq, (cgbn_mem_t<BITS> *)priv_key->dev_hq_);
  cgbn_load(bn_env, psquare, (cgbn_mem_t<BITS> *)priv_key->dev_psquare_);
  cgbn_load(bn_env, qsquare, (cgbn_mem_t<BITS> *)priv_key->dev_qsquare_);
  l_func(bn_env, mp, cipher, p, psquare, hp); 
  l_func(bn_env, mq, cipher, q, qsquare, hq); 
  bool neg = false;
  if (cgbn_compare(bn_env, mp, mq) < 0) {
     cgbn_sub(bn_env, tmp, mq, mp);
     neg = true;
  } else {
      cgbn_sub(bn_env, tmp, mp, mq);
  }
  cgbn_mul(bn_env, tmp, tmp, q_inverse); 
  cgbn_rem(bn_env, tmp, tmp, p);
  if (neg) {
     cgbn_sub(bn_env, tmp, p, tmp);
  }
  cgbn_mul(bn_env, tmp, tmp, q);
  cgbn_add(bn_env, tmp, mq, tmp);
  cgbn_rem(bn_env, tmp, tmp, n);
  cgbn_store(bn_env, plains + tid, tmp);

#ifdef DEBUG
  if (blockIdx.x == 0 && threadIdx.x == 0) {
    for (int i=0; i<count; i++) {
      p_cgbn("[decrypt] dev_plains", plains + i);
      p_cgbn("[decrypt] dev_ciphers", ciphers + i);
    }
    p_cgbn("dev_pk_n", (cgbn_mem_t<BITS> *)pk_n);
    p_cgbn("dev_p_", (cgbn_mem_t<BITS> *)priv_key->dev_p_);
    p_cgbn("dev_q_", (cgbn_mem_t<BITS> *)priv_key->dev_q_);
    p_cgbn("dev_hp_", (cgbn_mem_t<BITS> *)priv_key->dev_hp_);
    p_cgbn("dev_hq_", (cgbn_mem_t<BITS> *)priv_key->dev_hq_);
    p_cgbn("dev_psquare_", (cgbn_mem_t<BITS> *)priv_key->dev_psquare_);
    p_cgbn("dev_qsquare_", (cgbn_mem_t<BITS> *)priv_key->dev_qsquare_);
  }
#endif
} 

void CGBNWrapper::Decrypt(const std::vector<Ciphertext>& cts, const SecretKey& sk, const PublicKey& pk, std::vector<Plaintext>* pts) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = cts.size();

  cgbn_error_report_t *report;
  cgbn_mem_t<BITS> *dev_plains;
  cgbn_mem_t<BITS> *dev_ciphers;
  cgbn_mem_t<BITS> cpu_ciphers;

  CUDA_CHECK(cudaMalloc((void **)&dev_plains, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_ciphers, sizeof(cgbn_mem_t<BITS>) * count));

  CUDA_CHECK(cudaMemset(dev_plains->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_ciphers->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));

  for (int i=0; i<count; i++) {
    store2dev((dev_mem_t<BITS> *)(dev_ciphers + i), cts[i].c_); 
  }

  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_decrypt<<<(count+IPB-1)/IPB, TPB>>>(sk.dev_sk_,  const_cast<PublicKey *>(&pk)->dev_n_, report, dev_plains, dev_ciphers, count);
  CUDA_CHECK(cudaDeviceSynchronize());
  CGBN_CHECK(report);

  for (int i=0; i<count; i++) {
    store2host(&(*pts)[i], (dev_mem_t<BITS> *)(dev_plains + i));
  }

  CUDA_CHECK(cgbn_error_report_free(report));
  CUDA_CHECK(cudaFree(dev_plains));
  CUDA_CHECK(cudaFree(dev_ciphers));
}

__global__ __noinline__ void raw_add(dev_mem_t<BITS> *pk_nsquare, cgbn_error_report_t *report, gpu_mpz *ciphers_r, gpu_mpz *ciphers_a, gpu_mpz *ciphers_b,int count ) {
  int tid=(blockIdx.x*blockDim.x + threadIdx.x)/TPI;
  if(tid>=count)
    return;
  context_t      bn_context(cgbn_report_monitor, report, tid);  
  env_t          bn_env(bn_context.env<env_t>());                   
  env_t::cgbn_t  nsquare, r, a, b;               
  cgbn_load(bn_env, nsquare, (cgbn_mem_t<BITS> *)pk_nsquare);      
  cgbn_load(bn_env, a, ciphers_a + tid);      
  cgbn_load(bn_env, b, ciphers_b + tid);
  cgbn_mul(bn_env, r, a, b);
  cgbn_rem(bn_env, r, r, nsquare);

/*    
 uint32_t np0;
// convert a and b to Montgomery space
np0=cgbn_bn2mont(bn_env, a, a, nsquare);
cgbn_bn2mont(bn_env, b, b, nsquare);
cgbn_mont_mul(bn_env, r, a, b, nsquare, np0);
// convert r back to normal space
cgbn_mont2bn(bn_env, r, r, nsquare, np0);
*/
  cgbn_store(bn_env, ciphers_r + tid, r);

#ifdef DEBUG
  if (blockIdx.x == 0 && threadIdx.x == 0) {
    p_cgbn("ciphers_a", ciphers_a);
    p_cgbn("ciphers_b", ciphers_b);
    p_cgbn("ciphers_c", ciphers_r);
    p_cgbn("pk_nsquare", (cgbn_mem_t<BITS> *)pk_nsquare);
  }
#endif
}

void CGBNWrapper::Add(const PublicKey& pk, const std::vector<Ciphertext>& as, const std::vector<Ciphertext>& bs, std::vector<Ciphertext>* cs) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = as.size();

  cgbn_error_report_t *report;
  cgbn_mem_t<BITS> *dev_as;
  cgbn_mem_t<BITS> *dev_bs;
  cgbn_mem_t<BITS> *dev_cs;

  CUDA_CHECK(cudaMalloc((void **)&dev_as, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_bs, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_cs, sizeof(cgbn_mem_t<BITS>) * count)); 

  CUDA_CHECK(cudaMemset(dev_as->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_bs->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_cs->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));

  for (int i=0; i<count; i++) {
    store2dev((dev_mem_t<BITS> *)(dev_as + i), as[i].c_); 
    store2dev((dev_mem_t<BITS> *)(dev_bs + i), bs[i].c_); 
  }

  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_add<<<(count+IPB-1)/IPB, TPB>>>(pk.dev_nsquare_, report, dev_cs, dev_as, dev_bs, count);
  CUDA_CHECK(cudaDeviceSynchronize());
  CGBN_CHECK(report);

  for (int i=0; i<count; i++) {
    store2host(&(*cs)[i].c_, (dev_mem_t<BITS> *)(dev_cs + i));
  }

  CUDA_CHECK(cgbn_error_report_free(report));
  CUDA_CHECK(cudaFree(dev_as));
  CUDA_CHECK(cudaFree(dev_bs));
  CUDA_CHECK(cudaFree(dev_cs));
}

void CGBNWrapper::Add(const PublicKey& pk, const std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs, std::vector<Ciphertext>* cs) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = as.size();

  cgbn_error_report_t *report;
  cgbn_mem_t<BITS> *dev_as;
  cgbn_mem_t<BITS> *dev_bs;
  cgbn_mem_t<BITS> *dev_ctbs;
  cgbn_mem_t<BITS> *dev_cs;
  cgbn_mem_t<BITS> *dev_r;

  CUDA_CHECK(cudaMalloc((void **)&dev_as, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_bs, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_ctbs, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_cs, sizeof(cgbn_mem_t<BITS>) * count)); 
  CUDA_CHECK(cudaMalloc((void **)&dev_r, sizeof(cgbn_mem_t<BITS>))); 

  CUDA_CHECK(cudaMemset(dev_as->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_bs->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_ctbs->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_cs->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_r->_limbs, 0, sizeof(cgbn_mem_t<BITS>)));

  for (int i=0; i<count; i++) {
    store2dev((dev_mem_t<BITS> *)(dev_as + i), as[i].c_); 
    store2dev((dev_mem_t<BITS> *)(dev_bs + i), bs[i]); 
  }
  MPInt r;
  MPInt::RandomLtN(pk.max_int_, &r);
  store2dev((dev_mem_t<BITS> *)dev_r, r); 

  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_encrypt<<<(count+IPB-1)/IPB, TPB>>>(pk.dev_pk_, report,  dev_bs, dev_ctbs, dev_r, count); 
  raw_add<<<(count+IPB-1)/IPB, TPB>>>(pk.dev_nsquare_, report, dev_cs, dev_as, dev_ctbs, count);
  CUDA_CHECK(cudaDeviceSynchronize());
  CGBN_CHECK(report);

  for (int i=0; i<count; i++) {
    store2host(&(*cs)[i].c_, (dev_mem_t<BITS> *)(dev_cs + i));
  }

  CUDA_CHECK(cgbn_error_report_free(report));
  CUDA_CHECK(cudaFree(dev_as));
  CUDA_CHECK(cudaFree(dev_bs));
  CUDA_CHECK(cudaFree(dev_ctbs));
  CUDA_CHECK(cudaFree(dev_cs));
  CUDA_CHECK(cudaFree(dev_r));
}

__global__ void raw_mul(dev_mem_t<BITS> *pk_n, dev_mem_t<BITS> *pk_max_int, dev_mem_t<BITS> *pk_nsquare, 
                        cgbn_error_report_t *report, gpu_mpz *ciphers_r, gpu_mpz *ciphers_a, gpu_mpz *plains_b,int count) {
  int tid=(blockIdx.x*blockDim.x + threadIdx.x)/TPI;
  if(tid>=count)
    return;
  context_t      bn_context(cgbn_report_monitor, report, tid);  
  env_t          bn_env(bn_context.env<env_t>());                   
  env_t::cgbn_t  n,max_int, nsquare, r, cipher, plain, neg_c, neg_scalar,tmp;               

  cgbn_load(bn_env, n, (cgbn_mem_t<BITS> *)pk_n);      
  cgbn_load(bn_env, max_int, (cgbn_mem_t<BITS> *)pk_max_int);      
  cgbn_load(bn_env, nsquare,(cgbn_mem_t<BITS> *)pk_nsquare);      
  cgbn_load(bn_env, cipher, ciphers_a + tid);      
  cgbn_load(bn_env, plain, plains_b + tid);

  cgbn_sub(bn_env, tmp, n, max_int); 
 if(cgbn_compare(bn_env, plain, tmp) >= 0 ) {
    // Very large plaintext, take a sneaky shortcut using inverses
    cgbn_modular_inverse(bn_env,neg_c, cipher, nsquare);
    cgbn_sub(bn_env, neg_scalar, n, plain);
    powmod(bn_env, r, neg_c, neg_scalar, nsquare);
  } else {
    powmod(bn_env, r, cipher, plain, nsquare); 
  }

  cgbn_store(bn_env, ciphers_r + tid, r);

#ifdef DEBUG
  if (blockIdx.x == 0 && threadIdx.x == 0) {
    p_cgbn("ciphers_a", ciphers_a);
    p_cgbn("plains_b", plains_b);
    p_cgbn("ciphers_c", ciphers_r);
  }
#endif
}

void CGBNWrapper::Mul(const PublicKey& pk, const std::vector<Ciphertext>& as, const std::vector<Plaintext>& bs, std::vector<Ciphertext>* cs) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = as.size();

  cgbn_error_report_t *report;
  cgbn_mem_t<BITS> *dev_as;
  cgbn_mem_t<BITS> *dev_bs;
  cgbn_mem_t<BITS> *dev_cs;

  CUDA_CHECK(cudaMalloc((void **)&dev_as, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_bs, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_cs, sizeof(cgbn_mem_t<BITS>) * count)); 

  CUDA_CHECK(cudaMemset(dev_as->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_bs->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_cs->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));

  for (int i=0; i<count; i++) {
    store2dev((dev_mem_t<BITS> *)(dev_as + i), as[i].c_); 
    store2dev((dev_mem_t<BITS> *)(dev_bs + i), bs[i]); 
  }

  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_mul<<<(count+IPB-1)/IPB, TPB>>>(pk.dev_n_, pk.dev_max_int_, pk.dev_nsquare_, report, dev_cs, dev_as, dev_bs, count);
  CUDA_CHECK(cudaDeviceSynchronize());
  CGBN_CHECK(report);

  for (int i=0; i<count; i++) {
    store2host(&(*cs)[i].c_, (dev_mem_t<BITS> *)(dev_cs + i));
  }

  CUDA_CHECK(cgbn_error_report_free(report));
  CUDA_CHECK(cudaFree(dev_as));
  CUDA_CHECK(cudaFree(dev_bs));
  CUDA_CHECK(cudaFree(dev_cs));
}

__global__ void raw_negate(dev_mem_t<BITS> *pk_nsquare,  cgbn_error_report_t *report, gpu_mpz *ciphers_r, gpu_mpz *ciphers_a, int count) {
  int tid=(blockIdx.x*blockDim.x + threadIdx.x)/TPI;
  if(tid>=count)
    return;
  context_t      bn_context(cgbn_report_monitor, report, tid);  
  env_t          bn_env(bn_context.env<env_t>());                   
  env_t::cgbn_t  nsquare, r, a;               
  cgbn_load(bn_env, nsquare, (cgbn_mem_t<BITS> *)pk_nsquare);      
  cgbn_load(bn_env, a, ciphers_a + tid); 
  cgbn_modular_inverse(bn_env, r, a, nsquare);

  cgbn_store(bn_env, ciphers_r + tid, r);

#ifdef DEBUG
  if (blockIdx.x == 0 && threadIdx.x == 0) {
    p_cgbn("ciphers_a", ciphers_a);
    p_cgbn("ciphers_c", ciphers_r);
  }
#endif
}

void CGBNWrapper::Negate(const PublicKey& pk, const std::vector<Ciphertext>& as, std::vector<Ciphertext>* cs) {

  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = as.size();

  cgbn_error_report_t *report;
  cgbn_mem_t<BITS> *dev_as;
  cgbn_mem_t<BITS> *dev_cs;

  CUDA_CHECK(cudaMalloc((void **)&dev_as, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_cs, sizeof(cgbn_mem_t<BITS>) * count)); 

  CUDA_CHECK(cudaMemset(dev_as->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMemset(dev_cs->_limbs, 0, sizeof(cgbn_mem_t<BITS>) * count));

  for (int i=0; i<count; i++) {
    store2dev((dev_mem_t<BITS> *)(dev_as + i), as[i].c_); 
  }

  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_negate<<<(count+IPB-1)/IPB, TPB>>>(pk.dev_nsquare_, report, dev_cs, dev_as, count);
  CUDA_CHECK(cudaDeviceSynchronize());
  CGBN_CHECK(report);

  for (int i=0; i<count; i++) {
    store2host(&(*cs)[i].c_, (dev_mem_t<BITS> *)(dev_cs + i));
  }

  CUDA_CHECK(cgbn_error_report_free(report));
  CUDA_CHECK(cudaFree(dev_as));
  CUDA_CHECK(cudaFree(dev_cs));
}

void CGBNWrapper::DevMalloc(PublicKey *pk) {
  CUDA_CHECK(cudaMalloc((void **)&pk->dev_g_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&pk->dev_n_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&pk->dev_nsquare_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&pk->dev_max_int_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&pk->dev_pk_, sizeof(PublicKey))); 
}

void CGBNWrapper::DevFree(PublicKey *pk) {
  if (pk->dev_pk_) {
    CUDA_CHECK(cudaFree(pk->dev_g_));
    CUDA_CHECK(cudaFree(pk->dev_n_));
    CUDA_CHECK(cudaFree(pk->dev_nsquare_));
    CUDA_CHECK(cudaFree(pk->dev_max_int_));
    CUDA_CHECK(cudaFree(pk->dev_pk_));
  }
}

void CGBNWrapper::DevCopy(PublicKey *dst_pk, const PublicKey &pk) {
  CUDA_CHECK(cudaMemcpy(dst_pk->dev_g_, pk.dev_g_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_pk->dev_n_, pk.dev_n_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_pk->dev_nsquare_, pk.dev_nsquare_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_pk->dev_max_int_, pk.dev_max_int_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_pk->dev_pk_, dst_pk, sizeof(PublicKey), cudaMemcpyHostToDevice));
}

void CGBNWrapper::DevMalloc(SecretKey *sk) {
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_g_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_p_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_q_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_psquare_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_qsquare_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_q_inverse_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_hp_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_hq_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_sk_, sizeof(SecretKey)));
}

void CGBNWrapper::DevFree(SecretKey *sk) {
  if (sk->dev_sk_) {
    CUDA_CHECK(cudaFree(sk->dev_g_));
    CUDA_CHECK(cudaFree(sk->dev_p_));
    CUDA_CHECK(cudaFree(sk->dev_q_));
    CUDA_CHECK(cudaFree(sk->dev_psquare_));
    CUDA_CHECK(cudaFree(sk->dev_qsquare_));
    CUDA_CHECK(cudaFree(sk->dev_q_inverse_));
    CUDA_CHECK(cudaFree(sk->dev_hp_));
    CUDA_CHECK(cudaFree(sk->dev_hq_));
    CUDA_CHECK(cudaFree(sk->dev_sk_));
  }
}

void CGBNWrapper::DevCopy(SecretKey *dst_sk, const SecretKey &sk) {
  CUDA_CHECK(cudaMemcpy(dst_sk->dev_g_, sk.dev_g_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_sk->dev_p_, sk.dev_p_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_sk->dev_q_, sk.dev_q_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_sk->dev_psquare_, sk.dev_psquare_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_sk->dev_qsquare_, sk.dev_qsquare_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_sk->dev_q_inverse_, sk.dev_q_inverse_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_sk->dev_hp_, sk.dev_hp_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_sk->dev_hq_, sk.dev_hq_, sizeof(cgbn_mem_t<BITS>), cudaMemcpyDeviceToDevice));
  CUDA_CHECK(cudaMemcpy(dst_sk->dev_sk_, dst_sk, sizeof(SecretKey), cudaMemcpyHostToDevice));
}

void CGBNWrapper::StoreToDev(PublicKey *pk) {
  store2dev(pk->dev_n_, pk->n_);
  store2dev(pk->dev_pk_, *pk);
}

void CGBNWrapper::StoreToDev(SecretKey *sk) {
  store2dev(sk->dev_g_, sk->g_);
  store2dev(sk->dev_p_, sk->p_);
  store2dev(sk->dev_q_, sk->q_);
  store2dev(sk->dev_sk_, *sk);
}

void CGBNWrapper::StoreToHost(PublicKey *pk) {
  store2host(&pk->g_, pk->dev_g_);
  store2host(&pk->nsquare_, pk->dev_nsquare_);
  store2host(&pk->max_int_, pk->dev_max_int_);
}

void CGBNWrapper::StoreToHost(SecretKey *sk) {
  store2host(&sk->psquare_, sk->dev_psquare_);
  store2host(&sk->qsquare_, sk->dev_qsquare_);
  store2host(&sk->q_inverse_, sk->dev_q_inverse_);
  store2host(&sk->hp_, sk->dev_hp_);
  store2host(&sk->hq_, sk->dev_hq_);
}

} // namespace heu::lib::algorithms::paillier_dl