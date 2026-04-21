#include <benchmark/benchmark.h>

#include <chrono>
#include <iostream>
#include <random>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/operators.h"
#include "crypto/plaintext.h"
#include "crypto/public_key.h"
#include "crypto/secret_key.h"

using namespace crypto::bfv;

static void BM_Decryption(benchmark::State &state) {
  BfvParametersBuilder builder;
  builder.set_degree(8192).set_plaintext_modulus(1032193).set_moduli_sizes(
      {60, 50, 50, 58});
  auto params = builder.build_arc();

  std::mt19937_64 rng(12345);
  auto sk = SecretKey::random(params, rng);
  auto pk = PublicKey::from_secret_key(sk, rng);

  std::vector<uint64_t> vec(16, 1);
  auto encoding = Encoding::simd_at_level(0);
  auto pt1 = Plaintext::encode(vec, encoding, params);
  auto ct1 = pk.encrypt(pt1, rng);

  for (auto _ : state) {
    Plaintext out;
    sk.decrypt(ct1, out);
    benchmark::DoNotOptimize(out);
  }
}

BENCHMARK(BM_Decryption)->Iterations(50);

BENCHMARK_MAIN();
