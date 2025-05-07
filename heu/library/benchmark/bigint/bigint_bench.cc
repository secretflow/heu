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
using algorithms::BigInt;

const int kEncKeySize = 2048;

struct OuKey {
  ou::PublicKey pk;
  ou::SecretKey sk;

  void Reset() { ou::KeyGenerator::Generate(kEncKeySize, &sk, &pk); }
};

OuKey ctx;

static void BM_PowMod64(benchmark::State &state) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;

  uint64_t r = dis(gen);

  BigInt m(r), gm;
  for (auto _ : state) {
    gm = ctx.pk.capital_g_.PowMod(m, ctx.pk.n_);
  }
}

static void BM_PowMod64Mont(benchmark::State &state) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;

  uint64_t r = dis(gen);

  BigInt m(r), gm;
  for (auto _ : state) {
    gm = ctx.pk.m_space_->PowMod(*ctx.pk.cg_table_, m);
  }
}

static void BM_PowMod128(benchmark::State &state) {
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

  BigInt r, gm;
  r = BigInt::RandomMonicExactBits(128);

  for (auto _ : state) {
    gm = ctx.pk.capital_g_.PowMod(r, ctx.pk.n_);
  }
}

static void BM_PowMod128Mont(benchmark::State &state) {
  BigInt r, gm;
  r = BigInt::RandomMonicExactBits(128);

  for (auto _ : state) {
    gm = ctx.pk.m_space_->PowMod(*ctx.pk.cg_table_, r);
  }
}

static void BM_PowMod2048(benchmark::State &state) {
  BigInt r, gm;
  BigInt::RandomLtN(ctx.pk.n_, &r);

  for (auto _ : state) {
    gm = ctx.pk.capital_h_.PowMod(r, ctx.pk.n_);
  }
}

static void BM_MulMod2048(benchmark::State &state) {
  BigInt gm;
  for (auto _ : state) {
    gm = ctx.pk.capital_g_.MulMod(ctx.pk.capital_h_, ctx.pk.n_);
  }
}

static void BM_InvertMod2048(benchmark::State &state) {
  BigInt gm;
  for (auto _ : state) {
    gm = ctx.pk.capital_g_.InvMod(ctx.pk.n_);
  }
}

static void BM_NormalPrime(benchmark::State &state) {
  auto bits = state.range(0);
  BigInt p;
  for (auto _ : state) {
    p = BigInt::RandPrimeOver(bits, algorithms::PrimeType::Normal);
  }
}

static void BM_BbsPrime(benchmark::State &state) {
  auto bits = state.range(0);
  BigInt p;
  for (auto _ : state) {
    p = BigInt::RandPrimeOver(bits, heu::lib::algorithms::PrimeType::BBS);
  }
}

BENCHMARK(BM_PowMod64)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_PowMod64Mont)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_PowMod128)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_PowMod128Mont)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_PowMod2048)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_MulMod2048)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_InvertMod2048)->Unit(benchmark::kMillisecond);
BENCHMARK(BM_NormalPrime)
    ->Unit(benchmark::kMillisecond)
    ->Arg(512)
    ->Arg(1024)
    ->Arg(2048);
BENCHMARK(BM_BbsPrime)
    ->Unit(benchmark::kMillisecond)
    ->Arg(512)
    ->Arg(1024)
    ->Arg(2048);

}  // namespace heu::lib::bench

int main(int argc, char **argv) {
  ::benchmark::Initialize(&argc, argv);
  if (::benchmark::ReportUnrecognizedArguments(argc, argv)) {
    return 1;
  }

  heu::lib::bench::ctx.Reset();
  ::benchmark::RunSpecifiedBenchmarks();
  ::benchmark::Shutdown();
  return 0;
}
