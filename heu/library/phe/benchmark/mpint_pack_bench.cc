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

#include <vector>

#include "benchmark/benchmark.h"

#include "heu/library/algorithms/paillier_float/paillier.h"

namespace heu::lib::phe::bench {

namespace paillier_f = algorithms::paillier_f;
using algorithms::MPInt;

static std::vector<MPInt> GenerateMPInts() {
  paillier_f::PublicKey pub_key;
  paillier_f::SecretKey sec_key;

  paillier_f::KeyGenerator::Generate(3072, &sec_key, &pub_key);

  std::vector<int64_t> plains = {1, 10, 64, 199, 1234567890};
  std::vector<paillier_f::Ciphertext> ciphers(plains.size());

  paillier_f::Encryptor encryptor(pub_key);
  for (size_t i = 0; i < plains.size(); i++) {
    ciphers[i] = encryptor.Encrypt(plains[i]);
  }

  std::vector<MPInt> mpints;
  for (auto& cipher : ciphers) {
    mpints.push_back(cipher.underlying());
  }
  return mpints;
}

static std::vector<MPInt> mp_ints = GenerateMPInts();

static void BM_MPIntPackingUsingSerialize(benchmark::State& state) {
  double bytes_written = 0;
  for (auto _ : state) {
    for (auto& mp_int : mp_ints) {
      std::string str;
      mp_int.Serialize(&str);
      bytes_written += static_cast<double>(str.length());
    }
  }
  state.counters["bytes_written"] = bytes_written;
}

static void BM_MPIntPackingUsingToString(benchmark::State& state) {
  double bytes_written = 0;
  for (auto _ : state) {
    for (auto& mp_int : mp_ints) {
      std::string str = mp_int.ToHexString();
      bytes_written += static_cast<double>(str.length());
    }
  }
  state.counters["bytes_written"] = bytes_written;
}

BENCHMARK(BM_MPIntPackingUsingSerialize);
BENCHMARK(BM_MPIntPackingUsingToString);

}  // namespace heu::lib::phe::bench

BENCHMARK_MAIN();
