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

#include <chrono>
#include <functional>

#include "benchmark/benchmark.h"
#include "fmt/format.h"

#include "heu/library/algorithms/ou/ou.h"

namespace heu::lib::bench {

namespace ou = algorithms::ou;
using algorithms::BigInt;

constexpr static long kTestSize = 10000;
constexpr static size_t kKeySize = 2048;
constexpr int kRandomScale = 8011;

BigInt g_plain[kTestSize];
ou::SecretKey g_ou_secret_key;
ou::PublicKey g_ou_public_key;
ou::Ciphertext g_ou_ciphertext[kTestSize];

void Initialize() {
  for (int i = 0; i < kTestSize; ++i) {
    g_plain[i] = BigInt(i * kRandomScale);
  }
  ou::KeyGenerator::Generate(kKeySize, &g_ou_secret_key, &g_ou_public_key);
}

static void OuEncrypt(benchmark::State &state) {
  // encrypt
  ou::Encryptor encryptor(g_ou_public_key);
  for (auto _ : state) {
    for (int i = 0; i < kTestSize; ++i) {
      *(g_ou_ciphertext + i) = encryptor.Encrypt(g_plain[i]);
    }
  }
}

static void OuAddCipher(benchmark::State &state) {
  // add (ciphertext + ciphertext)
  ou::Evaluator evaluator(g_ou_public_key);
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator.AddInplace(&g_ou_ciphertext[0], g_ou_ciphertext[i]);
    }
  }
}

static void OuSubCipher(benchmark::State &state) {
  // sub (ciphertext - ciphertext)
  ou::Evaluator evaluator(g_ou_public_key);
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator.SubInplace(&g_ou_ciphertext[0], g_ou_ciphertext[i]);
    }
  }
}

static void OuAddInt(benchmark::State &state) {
  // add (ciphertext + plaintext)
  ou::Evaluator evaluator(g_ou_public_key);
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator.AddInplace(&g_ou_ciphertext[i], BigInt(i));
    }
  }
}

static void OuMulti(benchmark::State &state) {
  // mul (ciphertext * plaintext)
  ou::Evaluator evaluator(g_ou_public_key);
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator.MulInplace(&g_ou_ciphertext[i], BigInt(i));
    }
  }
}

static void OuDecrypt(benchmark::State &state) {
  // decrypt
  ou::Decryptor decryptor(g_ou_public_key, g_ou_secret_key);
  for (auto _ : state) {
    for (int i = 0; i < kTestSize; ++i) {
      decryptor.Decrypt(g_ou_ciphertext[i], g_plain + i);
    }
  }
}

BENCHMARK(OuEncrypt)->Unit(benchmark::kMillisecond);
BENCHMARK(OuAddCipher)->Unit(benchmark::kMillisecond);
BENCHMARK(OuSubCipher)->Unit(benchmark::kMillisecond);
BENCHMARK(OuAddInt)->Unit(benchmark::kMillisecond);
BENCHMARK(OuMulti)->Unit(benchmark::kMillisecond);
BENCHMARK(OuDecrypt)->Unit(benchmark::kMillisecond);

}  // namespace heu::lib::bench

int main(int argc, char **argv) {
  benchmark::Initialize(&argc, argv);
  heu::lib::bench::Initialize();
  benchmark::RunSpecifiedBenchmarks();
  return 0;
}
