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

#include "benchmark/benchmark.h"

#include "heu/library/algorithms/paillier_zahlen/paillier.h"
#include "heu/library/algorithms/util/big_int.h"

namespace heu::lib::bench {
namespace paillier = algorithms::paillier_z;
using algorithms::BigInt;

paillier::SecretKey g_sk;
BigInt g_base;
algorithms::BaseTable g_base_table;
BigInt g_res;

std::shared_ptr<algorithms::MontgomerySpace> ms;

void Initialize(int base_bits) {
  paillier::PublicKey pk;
  paillier::KeyGenerator::Generate(2048, &g_sk, &pk);
  g_base = BigInt::RandomMonicExactBits(base_bits);

  ms = BigInt::CreateMontgomerySpace(g_sk.n_square_);
  ms->MakeBaseTable(g_base, 11, 4 << 10, &g_base_table);

  benchmark::AddCustomContext("Base bits", "4096");
  benchmark::AddCustomContext("Mod bits ",
                              fmt::format("{}", g_sk.n_square_.BitCount()));
}

void PowModCrt(benchmark::State &state) {
  BigInt exp = BigInt::RandomExactBits(state.range(0));
  for (auto _ : state) {
    g_res = g_sk.PowModNSquareCrt(g_base, exp);
  }
}

void PowModCacheTable(benchmark::State &state) {
  BigInt exp = BigInt::RandomExactBits(state.range(0));
  for (auto _ : state) {
    g_res = ms->PowMod(g_base_table, exp);
  }
}

void PowModTommath(benchmark::State &state) {
  BigInt exp = BigInt::RandomExactBits(state.range(0));
  for (auto _ : state) {
    g_res = g_base.PowMod(exp, g_sk.n_square_);
  }
}

BENCHMARK(PowModCrt)
    ->Unit(benchmark::kMillisecond)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(2048)
    ->Arg(4096);
BENCHMARK(PowModCacheTable)
    ->Unit(benchmark::kMillisecond)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(2048)
    ->Arg(4096);
BENCHMARK(PowModTommath)
    ->Unit(benchmark::kMillisecond)
    ->Arg(64)
    ->Arg(1024)
    ->Arg(2048)
    ->Arg(4096);
}  // namespace heu::lib::bench

int main() {
  heu::lib::bench::Initialize(4096);
  benchmark::RunSpecifiedBenchmarks();
  return 0;
}
