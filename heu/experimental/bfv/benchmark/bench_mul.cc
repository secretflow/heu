#include <benchmark/benchmark.h>

#include <chrono>
#include <iostream>
#include <random>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/operators.h"
#include "crypto/plaintext.h"
#include "crypto/public_key.h"
#include "crypto/secret_key.h"

using namespace crypto::bfv;

static void BM_Multiplication(benchmark::State &state) {
  BfvParametersBuilder builder;
  builder.set_degree(8192).set_plaintext_modulus(1032193).set_moduli_sizes(
      {60, 50, 50, 58});
  auto params = builder.build_arc();

  std::mt19937_64 rng(12345);
  auto sk = SecretKey::random(params, rng);
  auto pk = PublicKey::from_secret_key(sk, rng);

  std::vector<uint64_t> vec1(8192, 1);
  std::vector<uint64_t> vec2(8192, 2);
  auto encoding = Encoding::simd_at_level(0);
  auto pt1 = Plaintext::encode(vec1, encoding, params);
  auto pt2 = Plaintext::encode(vec2, encoding, params);
  auto ct1 = pk.encrypt(pt1, rng);
  auto ct2 = pk.encrypt(pt2, rng);

  for (auto _ : state) {
    auto out = ct1 * ct2;
    benchmark::DoNotOptimize(out);
  }

  // Clear the static operator cache before thread teardown to prevent double
  // free!
  crypto::bfv::clear_operator_cache();
}

BENCHMARK(BM_Multiplication)->Iterations(10);

BENCHMARK_MAIN();
