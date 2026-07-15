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

static void BM_Addition(benchmark::State &state) {
  BfvParametersBuilder builder;
  builder.set_degree(8192).set_plaintext_modulus(1032193).set_moduli_sizes(
      {60, 50, 50, 58});
  auto params = builder.build_arc();

  std::mt19937_64 rng(12345);
  auto sk = SecretKey::random(params, rng);
  auto pk = PublicKey::from_secret_key(sk, rng);

  auto pt1 = Plaintext::zero(Encoding::poly(), params);
  auto pt2 = Plaintext::zero(Encoding::poly(), params);

  auto ct1 = pk.encrypt(pt1, rng);
  auto ct2 = pk.encrypt(pt2, rng);

  for (auto _ : state) {
    auto r = ct1 + ct2;
    benchmark::DoNotOptimize(r);
  }
}

BENCHMARK(BM_Addition);

static void BM_AdditionInplace(benchmark::State &state) {
  BfvParametersBuilder builder;
  builder.set_degree(8192).set_plaintext_modulus(1032193).set_moduli_sizes(
      {60, 50, 50, 58});
  auto params = builder.build_arc();

  std::mt19937_64 rng(12345);
  auto sk = SecretKey::random(params, rng);
  auto pk = PublicKey::from_secret_key(sk, rng);

  auto pt1 = Plaintext::zero(Encoding::poly(), params);
  auto pt2 = Plaintext::zero(Encoding::poly(), params);

  auto ct1 = pk.encrypt(pt1, rng);
  auto ct2 = pk.encrypt(pt2, rng);

  for (auto _ : state) {
    auto r = ct1;
    r += ct2;
    benchmark::DoNotOptimize(r);
  }
}

BENCHMARK(BM_AdditionInplace);

static void BM_AddPolyBase(benchmark::State &state) {
  BfvParametersBuilder builder;
  builder.set_degree(8192).set_plaintext_modulus(1032193).set_moduli_sizes(
      {60, 50, 50, 58});
  auto params = builder.build_arc();

  std::mt19937_64 rng(12345);
  auto sk = SecretKey::random(params, rng);
  auto pk = PublicKey::from_secret_key(sk, rng);

  auto pt1 = Plaintext::zero(Encoding::poly(), params);
  auto pt2 = Plaintext::zero(Encoding::poly(), params);

  auto ct1 = pk.encrypt(pt1, rng);
  auto ct2 = pk.encrypt(pt2, rng);

  auto p1 = ct1.polynomial(0);
  auto p2 = ct2.polynomial(0);

  for (auto _ : state) {
    p1 += p2;
    benchmark::DoNotOptimize(p1);
  }
}

BENCHMARK(BM_AddPolyBase);

BENCHMARK_MAIN();
