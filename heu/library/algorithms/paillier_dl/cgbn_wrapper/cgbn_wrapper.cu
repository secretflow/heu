#include <gmp.h>
#include "cgbn/cgbn.h"
// #include "cgbn_wrapper_defs.h"
#include "cgbn_wrapper.h"
#include "gpu_support.h"

#define DEBUG

namespace heu::lib::algorithms::paillier_z {

typedef cgbn_context_t<TPI>         context_t;
typedef cgbn_env_t<context_t, BITS> env_t;
typedef typename env_t::cgbn_t                bn_t;
typedef typename env_t::cgbn_local_t          bn_local_t;
typedef cgbn_mem_t<BITS> gpu_mpz; 

void p_mpint(char *name, MPInt *d) {
  printf("[%s]\n", name);
  for (int i=0; i<(d->SizeUsed() + 3) / 4; i++) {
    printf("%08x ", ((uint32_t *)(d->n_.dp))[i]);
  }
  printf("\n");
}

__device__ void p_cgbn(char *name, cgbn_mem_t<BITS> *d) {
  printf("[%s]\n", name);
  for (int i=0; i<(sizeof(d->_limbs) + 3) / 4; i++) {
    printf("%08x ", d->_limbs[i]);
  }
  printf("\n");
}

static void p_mpz(char *name, mpz_t d) {
  printf("[%s]\n", name);
  for (int i=0; i<d->_mp_alloc * 2; i++) {
    printf("%08x ", ((uint32_t *)(d->_mp_d))[i]);
  }
  printf("\n");
}

void mpint_cal_used(MPInt* out) {
  int used = 0;
  for (int i=0; i<out->SizeAllocated(); i++) {
    if (((unsigned char *)out->n_.dp)[i] != 0) {
      used = i + 1;
    }
  }
  out->n_.used = (used + sizeof(mp_digit) - 1) / sizeof(mp_digit);
}

void mpint_handle_neg(MPInt* out) {
  int used = out->SizeUsed();
  if ((((unsigned char *)out->n_.dp)[used - 1] & 0x80) > 0 || out->n_.sign == MP_NEG) {
    for (int i=0; i<used; i++) {
      ((unsigned char *)out->n_.dp)[i] = ~((unsigned char *)out->n_.dp)[i];
    }
    out->n_.sign = MP_NEG;
  }
}

void pt_cal_used(Plaintext* out) {
  int used = 0;
  for (int i=0; i<out->SizeAllocated(); i++) {
    if (((unsigned char *)out->n_.dp)[i] != 0) {
      used = i + 1;
    }
  }
  out->n_.used = (used + sizeof(mp_digit) - 1) / sizeof(mp_digit);
}

void pt_handle_neg(Plaintext* out) {
  int used = out->SizeUsed();
  if ((((unsigned char *)out->n_.dp)[used - 1] & 0x80) > 0 || out->n_.sign == MP_NEG) {
    for (int i=0; i<used; i++) {
      ((unsigned char *)out->n_.dp)[i] = ~((unsigned char *)out->n_.dp)[i];
    }
    out->n_.sign = MP_NEG;
  }
}

void store2gmp(mpz_t z, cgbn_mem_t<BITS> *address ) {
  mpz_import(z, (BITS+31)/32, -1, sizeof(uint32_t), 0, 0, (uint32_t *)address);
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

__global__ __noinline__ void raw_encrypt(PublicKey *pub_key, cgbn_error_report_t *report, gpu_mpz *plains, gpu_mpz *ciphers,int count, int rand_seed ) {
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
  cgbn_set_ui32(bn_env, r, rand_seed);
  cgbn_modular_power(bn_env, tmp, r, n, nsquare); 
  cgbn_mul(bn_env, tmp, cipher, tmp); 
  cgbn_rem(bn_env, r, tmp, nsquare);
  cgbn_store(bn_env, ciphers + tid, r);   // store r into sum

#ifdef DEBUG
  if (blockIdx.x == 0 && threadIdx.x == 0) {
    p_cgbn("[encrypt] dev_plains", plains);
    p_cgbn("[encrypt] dev_ciphers", ciphers);
  }
#endif
}

void CGBNWrapper::Encrypt(const MPInt m, const PublicKey pk,  MPInt &rn, Ciphertext &ct) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = 1;

  mpint_handle_neg(const_cast<MPInt *>(&m));

  cgbn_error_report_t *report;
  cgbn_mem_t<BITS> *dev_plains;
  cgbn_mem_t<BITS> *dev_ciphers;
  PublicKey *dev_pub_key;

  CUDA_CHECK(cudaMalloc((void **)&dev_plains, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&dev_ciphers, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&dev_pub_key, sizeof(pk))); 
  CUDA_CHECK(cudaMemcpy(dev_plains->_limbs, m.n_.dp, const_cast<MPInt *>(&m)->SizeUsed(), cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(dev_pub_key, &pk,  sizeof(pk), cudaMemcpyHostToDevice));
  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_encrypt<<<(count+IPB-1)/IPB, TPB>>>(dev_pub_key, report,  dev_plains, dev_ciphers, count, 12345); 
  CUDA_CHECK(cudaDeviceSynchronize());
  if (ct.c_.SizeAllocated() > sizeof(dev_ciphers->_limbs)) {
    printf("%s:%d No enough memory, need: %d, real: %d\n", __FILE__, __LINE__, sizeof(dev_ciphers->_limbs), ct.c_.SizeAllocated());
    abort();
  }
  CUDA_CHECK(cudaMemcpy(ct.c_.n_.dp, dev_ciphers->_limbs, ct.c_.SizeAllocated(), cudaMemcpyDeviceToHost)); 

  CGBN_CHECK(report);

  CUDA_CHECK(cgbn_error_report_free(report));
  CUDA_CHECK(cudaFree(dev_plains));
  CUDA_CHECK(cudaFree(dev_ciphers));
  CUDA_CHECK(cudaFree(dev_pub_key));
}

void CGBNWrapper::Encrypt(absl::Span<const Plaintext> pts, const PublicKey pk, std::vector<MPInt> &rns, std::vector<Ciphertext> &cts) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = pts.size();

  std::vector<Plaintext> handled_pts;
  for (int i=0; i<count; i++) {
    Plaintext pt = pts[i];
    pt_handle_neg(&pt);
    handled_pts.push_back(pt);
  }

  cgbn_error_report_t *report;
  cgbn_mem_t<BITS> *dev_plains;
  cgbn_mem_t<BITS> *dev_ciphers;
  PublicKey *dev_pub_key;

  CUDA_CHECK(cudaMalloc((void **)&dev_plains, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_ciphers, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_pub_key, sizeof(pk))); 
  for (int i=0; i<count; i++) {
    CUDA_CHECK(cudaMemcpy(dev_plains[i]._limbs, handled_pts[i].n_.dp, handled_pts[i].SizeUsed(), cudaMemcpyHostToDevice));
  }
  CUDA_CHECK(cudaMemcpy(dev_pub_key, &pk,  sizeof(pk), cudaMemcpyHostToDevice));
  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_encrypt<<<(count+IPB-1)/IPB, TPB>>>(dev_pub_key, report,  dev_plains, dev_ciphers, count, 12345); 
  CUDA_CHECK(cudaDeviceSynchronize());

  for (int i=0; i<count; i++) {
    if (cts[i].c_.SizeAllocated() > sizeof(dev_ciphers[i]._limbs)) {
      printf("%s:%d No enough memory, need: %d, real: %d\n", __FILE__, __LINE__, sizeof(dev_ciphers[i]._limbs), cts[i].c_.SizeAllocated());
      abort();
    }
    CUDA_CHECK(cudaMemcpy(cts[i].c_.n_.dp, dev_ciphers[i]._limbs, cts[i].c_.SizeAllocated(), cudaMemcpyDeviceToHost)); 
  }

  CGBN_CHECK(report);

  CUDA_CHECK(cgbn_error_report_free(report));
  CUDA_CHECK(cudaFree(dev_plains));
  CUDA_CHECK(cudaFree(dev_ciphers));
  CUDA_CHECK(cudaFree(dev_pub_key));
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
  cgbn_sub(bn_env, tmp, mp, mq);
  cgbn_mul(bn_env, tmp, tmp, q_inverse); 
  cgbn_rem(bn_env, tmp, tmp, p);
  cgbn_mul(bn_env, tmp, tmp, q);
  cgbn_add(bn_env, tmp, mq, tmp);
  cgbn_rem(bn_env, tmp, tmp, n);
  cgbn_store(bn_env, plains + tid, tmp);

#ifdef DEBUG
  if (blockIdx.x == 0 && threadIdx.x == 0) {
    p_cgbn("[decrypt] dev_plains", plains);
    p_cgbn("[decrypt] dev_ciphers", ciphers);
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

void CGBNWrapper::Decrypt(const Ciphertext& ct, const SecretKey sk, const PublicKey pk, MPInt* out) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = 1;

  cgbn_error_report_t *report;
  cgbn_mem_t<BITS> *dev_plains;
  cgbn_mem_t<BITS> *dev_ciphers;
  SecretKey *dev_priv_key;
  cgbn_mem_t<BITS> cpu_ciphers;

  CUDA_CHECK(cudaMalloc((void **)&dev_plains, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&dev_ciphers, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&dev_priv_key, sizeof(sk))); 
  CUDA_CHECK(cudaMemcpy(dev_ciphers->_limbs, ct.c_.n_.dp, const_cast<MPInt *>(&ct.c_)->SizeUsed(), cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(dev_priv_key, &sk,  sizeof(sk), cudaMemcpyHostToDevice));
  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_decrypt<<<(count+IPB-1)/IPB, TPB>>>(dev_priv_key,  const_cast<PublicKey *>(&pk)->dev_n_, report, dev_plains, dev_ciphers, count);
  CUDA_CHECK(cudaDeviceSynchronize());
  if (out->SizeAllocated() > sizeof(dev_plains->_limbs)) {
    printf("%s:%d No enough memory, need: %d, real: %d\n", __FILE__, __LINE__, sizeof(dev_plains->_limbs), out->SizeAllocated());
    abort();
  }
  
  CUDA_CHECK(cudaMemcpy(out->n_.dp, dev_plains->_limbs, out->SizeAllocated(), cudaMemcpyDeviceToHost)); 
  CGBN_CHECK(report);

  mpint_cal_used(out);
  mpint_handle_neg(out);

  CUDA_CHECK(cgbn_error_report_free(report));
  CUDA_CHECK(cudaFree(dev_plains));
  CUDA_CHECK(cudaFree(dev_ciphers));
  CUDA_CHECK(cudaFree(dev_priv_key));
}

void CGBNWrapper::Decrypt(absl::Span<const Ciphertext>& cts, const SecretKey sk, const PublicKey pk, absl::Span<Plaintext>* pts) {
  int32_t              TPB=128;
  int32_t              IPB=TPB/TPI;
  int count = cts.size();

  cgbn_error_report_t *report;
  cgbn_mem_t<BITS> *dev_plains;
  cgbn_mem_t<BITS> *dev_ciphers;
  SecretKey *dev_priv_key;
  cgbn_mem_t<BITS> cpu_ciphers;

  CUDA_CHECK(cudaMalloc((void **)&dev_plains, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_ciphers, sizeof(cgbn_mem_t<BITS>) * count));
  CUDA_CHECK(cudaMalloc((void **)&dev_priv_key, sizeof(sk))); 
  for (int i=0; i<count; i++) {
    Ciphertext ct = cts[i];
    if (ct.c_.SizeUsed() > sizeof(dev_ciphers[i]._limbs)) {
      printf("%s:%d No enough memory, need: %d, real: %d\n", __FILE__, __LINE__, sizeof(dev_ciphers[i]._limbs), ct.c_.SizeUsed());
      abort();
    }   
    CUDA_CHECK(cudaMemcpy(dev_ciphers[i]._limbs, ct.c_.n_.dp, ct.c_.SizeUsed(), cudaMemcpyHostToDevice));
  }
  CUDA_CHECK(cudaMemcpy(dev_priv_key, &sk,  sizeof(sk), cudaMemcpyHostToDevice));
  CUDA_CHECK(cgbn_error_report_alloc(&report));

  raw_decrypt<<<(count+IPB-1)/IPB, TPB>>>(dev_priv_key,  const_cast<PublicKey *>(&pk)->dev_n_, report, dev_plains, dev_ciphers, count);
  CUDA_CHECK(cudaDeviceSynchronize());
  CGBN_CHECK(report);

  for (int i=0; i<count; i++) {
    MPInt *pt_ptr = &(*pts)[i];
    if (sizeof(dev_plains[i]._limbs) > pt_ptr->SizeAllocated()) {
      mp_init_size(&pt_ptr->n_, sizeof(dev_plains[i]._limbs) / sizeof(uint32_t)); 
      if (sizeof(dev_plains[i]._limbs) > pt_ptr->SizeAllocated()) {
        printf("%s:%d No enough memory, need: %d, real: %d\n", __FILE__, __LINE__, sizeof(dev_plains[i]._limbs), pt_ptr->SizeAllocated());
        abort();
      }
    }    
    CUDA_CHECK(cudaMemcpy(pt_ptr->n_.dp, dev_plains[i]._limbs, sizeof(dev_plains[i]._limbs), cudaMemcpyDeviceToHost)); 

    mpint_cal_used(pt_ptr);
    mpint_handle_neg(pt_ptr);
  }

  CUDA_CHECK(cgbn_error_report_free(report));
  CUDA_CHECK(cudaFree(dev_plains));
  CUDA_CHECK(cudaFree(dev_ciphers));
  CUDA_CHECK(cudaFree(dev_priv_key));
}


static void store2dev(dev_mem_t<BITS> *address, mpz_t z) {
  if (std::abs(z->_mp_size) * sizeof(mp_limb_t) > sizeof(address->_limbs)) {
    printf("%s:%d No enough memory, need: %d, real: %d\n", __FILE__, __LINE__, std::abs(z->_mp_size)  * sizeof(mp_limb_t), sizeof(address->_limbs));
    abort();
  }
  CUDA_CHECK(cudaMemset(address->_limbs, 0, sizeof(address->_limbs)));
  CUDA_CHECK(cudaMemcpy(address->_limbs, z->_mp_d, std::abs(z->_mp_size) * sizeof(mp_limb_t), cudaMemcpyHostToDevice));
}

void CGBNWrapper::DevMalloc(PublicKey *pk) {
  CUDA_CHECK(cudaMalloc((void **)&pk->dev_g_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&pk->dev_n_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&pk->dev_nsquare_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&pk->dev_max_int_, sizeof(cgbn_mem_t<BITS>)));
}

void CGBNWrapper::DevFree(PublicKey *pk) {
  CUDA_CHECK(cudaFree(pk->dev_g_));
  CUDA_CHECK(cudaFree(pk->dev_n_));
  CUDA_CHECK(cudaFree(pk->dev_nsquare_));
  CUDA_CHECK(cudaFree(pk->dev_max_int_));
}


void CGBNWrapper::DevMalloc(SecretKey *sk) {
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_p_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_q_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_psquare_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_qsquare_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_q_inverse_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_hp_, sizeof(cgbn_mem_t<BITS>)));
  CUDA_CHECK(cudaMalloc((void **)&sk->dev_hq_, sizeof(cgbn_mem_t<BITS>)));
}

void CGBNWrapper::DevFree(SecretKey *sk) {
  CUDA_CHECK(cudaFree(sk->dev_p_));
  CUDA_CHECK(cudaFree(sk->dev_q_));
  CUDA_CHECK(cudaFree(sk->dev_psquare_));
  CUDA_CHECK(cudaFree(sk->dev_qsquare_));
  CUDA_CHECK(cudaFree(sk->dev_q_inverse_));
  CUDA_CHECK(cudaFree(sk->dev_hp_));
  CUDA_CHECK(cudaFree(sk->dev_hq_));
}


void CGBNWrapper::StoreToDev(PublicKey *pk) {
  store2dev(pk->dev_g_, pk->g_);
  store2dev(pk->dev_n_, pk->n_);
  store2dev(pk->dev_nsquare_, pk->nsquare_);
  store2dev(pk->dev_max_int_, pk->max_int_);
}

void CGBNWrapper::StoreToDev(SecretKey *sk) {
  store2dev(sk->dev_p_, sk->p_);
  store2dev(sk->dev_q_, sk->q_);
  store2dev(sk->dev_psquare_, sk->psquare_);
  store2dev(sk->dev_qsquare_, sk->qsquare_);
  store2dev(sk->dev_q_inverse_, sk->q_inverse_);
  store2dev(sk->dev_hp_, sk->hp_);
  store2dev(sk->dev_hq_, sk->hq_);
}

} // namespace heu::lib::algorithms::paillier_z