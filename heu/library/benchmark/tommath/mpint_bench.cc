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

#include <random>

#include "benchmark/benchmark.h"

#include "heu/library/algorithms/ou/ou.h"
#include "heu/library/algorithms/util/mp_int.h"

namespace heu::lib::bench {

namespace ou = algorithms::ou;
using algorithms::MPInt;

const int kEncKeySize = 2048;

struct OuKey {
  ou::PublicKey pk;
  ou::SecretKey sk;

  void Reset() { ou::KeyGenerator::Generate(kEncKeySize, &sk, &pk); }
};

OuKey ctx;

static void BM_PowMod64(benchmark::State& state) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;

  uint64_t r = dis(gen);

  MPInt m(r), gm;
  for (auto _ : state) {
    MPInt::PowMod(ctx.pk.capital_g_, m, ctx.pk.n_, &gm);
  }
}

static void BM_PowMod64Mont(benchmark::State& state) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;

  uint64_t r = dis(gen);

  MPInt m(r), gm;
  for (auto _ : state) {
    ctx.pk.m_space_->PowMod(*ctx.pk.cg_table_, m, &gm);
  }
}

static void BM_PowMod128(benchmark::State& state) {
#if 0
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;

  // NOTE: if r is negative, PowMod time cost will double
  int128_t r;
  do {
    r = dis(gen);
    r = (r << 64) + dis(gen);
  } while (r < 0);
#endif

  MPInt r, gm;
  MPInt::RandomMonicExactBits(128, &r);

  for (auto _ : state) {
    MPInt::PowMod(ctx.pk.capital_g_, r, ctx.pk.n_, &gm);
  }
}

static void BM_PowMod128Mont(benchmark::State& state) {
  MPInt r, gm;
  MPInt::RandomMonicExactBits(128, &r);

  for (auto _ : state) {
    ctx.pk.m_space_->PowMod(*ctx.pk.cg_table_, r, &gm);
  }
}

static void BM_PowMod2048(benchmark::State& state) {
  MPInt r, gm;
  MPInt::RandomLtN(ctx.pk.n_, &r);

  for (auto _ : state) {
    MPInt::PowMod(ctx.pk.capital_h_, r, ctx.pk.n_, &gm);
  }
}

static void BM_MulMod2048(benchmark::State& state) {
  MPInt gm;
  for (auto _ : state) {
    MPInt::MulMod(ctx.pk.capital_g_, ctx.pk.capital_h_, ctx.pk.n_, &gm);
  }
}

static void BM_InvertMod2048(benchmark::State& state) {
  MPInt gm;
  for (auto _ : state) {
    MPInt::InvertMod(ctx.pk.capital_g_, ctx.pk.n_, &gm);
  }
}

static void BM_SafePrime(benchmark::State& state) {
  auto bits = state.range(0);
  MPInt p;
  for (auto _ : state) {
    MPInt::RandPrimeOver(bits, &p, heu::lib::algorithms::PrimeType::Safe);
  }
}

static void BM_FastSafePrime(benchmark::State& state) {
  auto bits = state.range(0);
  MPInt p;
  for (auto _ : state) {
    MPInt::RandPrimeOver(bits, &p, algorithms::PrimeType::FastSafe);
  }
}

BENCHMARK(BM_PowMod64)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_PowMod64Mont)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_PowMod128)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_PowMod128Mont)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_PowMod2048)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_MulMod2048)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_InvertMod2048)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_FastSafePrime)
    ->Unit(benchmark::kMillisecond)
    ->Arg(512)
    ->Arg(1024)
    ->Arg(2048);
BENCHMARK(BM_SafePrime)
    ->Unit(benchmark::kMillisecond)
    ->Arg(512)
    ->Arg(1024)
    ->Arg(2048);

}  // namespace heu::lib::bench

int main(int argc, char** argv) {
  ::benchmark::Initialize(&argc, argv);
  if (::benchmark::ReportUnrecognizedArguments(argc, argv)) {
    return 1;
  }

  heu::lib::bench::ctx.Reset();
  ::benchmark::RunSpecifiedBenchmarks();
  ::benchmark::Shutdown();
  return 0;
}
