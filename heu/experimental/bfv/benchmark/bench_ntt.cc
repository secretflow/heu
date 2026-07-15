#include <benchmark/benchmark.h>

#include <chrono>
#include <iostream>
#include <random>

#include "crypto/bfv_parameters.h"
#include "math/context.h"
#include "math/modulus.h"
#include "math/ntt.h"

using namespace crypto::bfv;

static void BM_NttForward(benchmark::State &state) {
  BfvParametersBuilder builder;
  builder.set_degree(8192).set_plaintext_modulus(1032193).set_moduli_sizes(
      {60, 50, 50, 58});
  auto params = builder.build_arc();

  std::mt19937_64 rng(12345);
  std::vector<uint64_t> vec(8192);
  for (auto &v : vec) v = rng() % 0x3fffffff000001;  // smaller than modulus

  auto op =
      ::bfv::math::ntt::NttOperator::New(params->ctx_at_level(0)->q()[0], 8192);

  for (auto _ : state) {
    op->ForwardInPlace(vec.data());
    benchmark::DoNotOptimize(vec);
  }
}

BENCHMARK(BM_NttForward)->Iterations(50);

BENCHMARK_MAIN();
