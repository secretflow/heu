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

#include "heu/library/algorithms/paillier_zahlen/key_generator.h"

#include "yacl/base/exception.h"

#include "heu/library/algorithms/util/mp_int.h"
#include <gmp.h>
namespace heu::lib::algorithms::paillier_z {

namespace {

constexpr size_t kPQDifferenceBitLenSub = 2;  // >=1022-bit P-Q
}

void getprimeover(mpz_t rop, int bits, int &seed_start){
  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, seed_start);
  seed_start++;
  mpz_t rand_num;
  mpz_init(rand_num);
  mpz_urandomb(rand_num, state, bits);
  mpz_setbit(rand_num, bits-1);
  mpz_nextprime(rop, rand_num); 
  mpz_clear(rand_num);
}

void KeyGenerator::Generate(size_t key_size, SecretKey* sk, PublicKey* pk) {
  YACL_ENFORCE(key_size % 2 == 0, "Key size must be even");

  mpz_t p;
  mpz_t q;    
  mpz_t n;    
  mpz_init(p);
  mpz_init(q);
  mpz_init(n);
  int n_len = 0;
  srand((unsigned)time(NULL));
  //int seed_start = rand();
  int seed_start = 2;
  int key_len = 1024;
  while(n_len != key_len) {
    getprimeover(p, key_len / 2, seed_start);
    mpz_set(q, p);
    while(mpz_cmp(p, q) == 0){
      getprimeover(q, key_len / 2, seed_start);
      mpz_mul(n, p, q);
      n_len = mpz_sizeinbase(n, 2);
    }
  }

  mpz_t g;
  mpz_init(g);
  pk->Init(n, g);
  sk->Init(g, p, q);
  mpz_clear(p);
  mpz_clear(q);
  mpz_clear(n);
  mpz_clear(g);
}

}  // namespace heu::lib::algorithms::paillier_z
