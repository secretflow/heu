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
#include <cstdio>
#include <functional>

#include "benchmark/benchmark.h"
#include "fmt/format.h"

#include "heu/library/phe/phe.h"

namespace heu::lib::phe::bench {

using algorithms::MPInt;

constexpr static long kTestSize = 1000;
constexpr static size_t kKeySize = 2048;
constexpr int kRandomScale = 8011;

HeKit he;
MPInt g_plain[kTestSize];
Ciphertext ciphertext[kTestSize];

void Initialize(SchemaType schema_type) {
  he.Setup(schema_type, kKeySize);
  for (int i = 0; i < kTestSize; ++i) {
    g_plain[i] = MPInt(i * kRandomScale);
  }
}

static void Encrypt(benchmark::State& state) {
  // encrypt
  const auto& encryptor = he.GetEncryptor();
  for (auto _ : state) {
    for (int i = 0; i < kTestSize; ++i) {
      *(ciphertext + i) = encryptor->Encrypt(g_plain[i]);
    }
  }
}

static void AddCipher(benchmark::State& state) {
  // add (ciphertext + ciphertext)
  const auto& evaluator = he.GetEvaluator();
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator->AddInplace(&ciphertext[0], ciphertext[i]);
    }
  }
}

static void SubCipher(benchmark::State& state) {
  // sub (ciphertext - ciphertext)
  const auto& evaluator = he.GetEvaluator();
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator->SubInplace(&ciphertext[0], ciphertext[i]);
    }
  }
}

static void AddInt(benchmark::State& state) {
  // add (ciphertext + plaintext)
  const auto& evaluator = he.GetEvaluator();
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator->AddInplace(&ciphertext[i], MPInt(i));
    }
  }
}

static void SubInt(benchmark::State& state) {
  // add (ciphertext - plaintext)
  const auto& evaluator = he.GetEvaluator();
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator->SubInplace(&ciphertext[i], MPInt(i));
    }
  }
}

static void Multi(benchmark::State& state) {
  // mul (ciphertext * plaintext)
  const auto& evaluator = he.GetEvaluator();
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator->MulInplace(&ciphertext[i], MPInt(i));
    }
  }
}

static void Decrypt(benchmark::State& state) {
  // decrypt
  const auto& decryptor = he.GetDecryptor();
  for (auto _ : state) {
    for (int i = 0; i < kTestSize; ++i) {
      decryptor->Decrypt(ciphertext[i], g_plain + i);
    }
  }
}

static void Run(SchemaType schema_type) {
  printf("\n++++++++++++++   ");
  printf("Running benchmark with schema_type = %s",
         SchemaToString(schema_type).c_str());
  printf("   ++++++++++++++\n");
  Initialize(schema_type);
  BENCHMARK(Encrypt)->Unit(benchmark::kMillisecond);
  BENCHMARK(AddCipher)->Unit(benchmark::kMillisecond);
  BENCHMARK(SubCipher)->Unit(benchmark::kMillisecond);
  BENCHMARK(AddInt)->Unit(benchmark::kMillisecond);
  BENCHMARK(SubInt)->Unit(benchmark::kMillisecond);
  BENCHMARK(Multi)->Unit(benchmark::kMillisecond);
  BENCHMARK(Decrypt)->Unit(benchmark::kMillisecond);
  benchmark::RunSpecifiedBenchmarks();
}

}  // namespace heu::lib::phe::bench

int main(int argc, char** argv) {
  benchmark::Initialize(&argc, argv);
  benchmark::AddCustomContext(
      "Run times", fmt::format("{}", heu::lib::phe::bench::kTestSize));
  benchmark::AddCustomContext(
      "Key size", fmt::format("{}", heu::lib::phe::bench::kKeySize));

  if (argc > 2) {
    printf("Usage: %s [algorithm]\n", argv[0]);
    exit(-1);
  }

  std::vector<heu::lib::phe::SchemaType> schemas;
  if (argc == 1 || argv[1][0] == '*') {
    schemas = heu::lib::phe::GetAllSchema();
  } else {
    schemas.push_back(heu::lib::phe::ParseSchemaType(argv[1]));
  }

  printf("Total benchmarks: %lu", schemas.size());
  for (const auto& schema : schemas) {
    heu::lib::phe::bench::Run(schema);
  }
  benchmark::Shutdown();
  return 0;
}
