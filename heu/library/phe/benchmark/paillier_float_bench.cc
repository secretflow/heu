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
#include <iostream>

#include "benchmark/benchmark.h"
#include "fmt/format.h"

#include "heu/library/algorithms/paillier_float/paillier.h"

namespace heu::lib::phe::bench {

namespace paillier_f = algorithms::paillier_f;
using algorithms::MPInt;

constexpr static long kTestSize = 10000;
constexpr static size_t kKeySize = 2048;
constexpr int kRandomScale = 8011;

MPInt g_plain[kTestSize];
paillier_f::SecretKey g_paillier_secret_key;
paillier_f::PublicKey g_paillier_public_key;
paillier_f::Ciphertext g_paillier_ciphertext[kTestSize];

typedef std::function<std::chrono::microseconds()> Action;

std::chrono::microseconds bench(const Action& action, int rounds = 10) {
  std::chrono::microseconds time_sum{0};
  for (int i = 0; i < rounds; i++) {
    time_sum += action();
  }
  auto avg_time = time_sum.count() / rounds;
  return std::chrono::microseconds{avg_time};
}

std::chrono::microseconds test_keygen(int key_bits) {
  paillier_f::PublicKey pub_key;
  paillier_f::SecretKey sec_key;

  std::chrono::high_resolution_clock::time_point time_start =
      std::chrono::high_resolution_clock::now();
  paillier_f::KeyGenerator::Generate(key_bits, &sec_key, &pub_key);
  std::chrono::high_resolution_clock::time_point time_end =
      std::chrono::high_resolution_clock::now();
  return std::chrono::duration_cast<std::chrono::microseconds>(time_end -
                                                               time_start);
}

std::chrono::microseconds test_encryption_small(int key_bits) {
  paillier_f::PublicKey pub_key;
  paillier_f::SecretKey sec_key;
  paillier_f::KeyGenerator::Generate(key_bits, &sec_key, &pub_key);

  paillier_f::Encryptor encryptor(pub_key);
  paillier_f::Ciphertext cipher;

  std::chrono::high_resolution_clock::time_point time_start =
      std::chrono::high_resolution_clock::now();
  cipher = encryptor.Encrypt(static_cast<int64_t>(45));
  std::chrono::high_resolution_clock::time_point time_end =
      std::chrono::high_resolution_clock::now();
  return std::chrono::duration_cast<std::chrono::microseconds>(time_end -
                                                               time_start);
}

void run_keygen_tests() {
  const std::vector<int> key_bits_array = {1024, 2048, 3072, 4096};
  for (int key_bits : key_bits_array) {
    fmt::print("Generate({} bits) AVG TIME: {} ms\n", key_bits,
               bench(bind(test_keygen, key_bits)).count() / 1000);
  }
}

void run_encryption_small_tests() {
  const std::vector<int> key_bits_array = {1024, 2048, 3072, 4096};
  for (int key_bits : key_bits_array) {
    fmt::print("Encryption Small ({} bits) AVG TIME: {} ms\n", key_bits,
               bench(bind(test_encryption_small, key_bits)).count() / 1000);
  }
}

void serialization_tests(int key_bits) {
  paillier_f::PublicKey pub_key;
  paillier_f::SecretKey sec_key;
  paillier_f::KeyGenerator::Generate(key_bits, &sec_key, &pub_key);

  paillier_f::Encryptor encryptor(pub_key);
  paillier_f::Ciphertext cipher;

  cipher = encryptor.Encrypt(static_cast<int64_t>(42));
  auto str = cipher.Serialize();
  fmt::print("key_bits={} sizeof(cipher of 42)={} bytes\n", key_bits,
             str.size());
}

void run_serialization_tests() {
  const std::vector<int> key_bits_array = {1024, 2048, 3072, 4096};
  for (int key_bits : key_bits_array) {
    serialization_tests(key_bits);
  }
}

void Initialize() {
  for (int i = 0; i < kTestSize; ++i) {
    g_plain[i] = MPInt(i * kRandomScale);
  }
  paillier_f::KeyGenerator::Generate(kKeySize, &g_paillier_secret_key,
                                     &g_paillier_public_key);
}

static void PaillierEncrypt(benchmark::State& state) {
  // encrypt
  paillier_f::Encryptor encryptor(g_paillier_public_key);
  for (auto _ : state) {
    for (int i = 0; i < kTestSize; ++i) {
      *(g_paillier_ciphertext + i) = encryptor.Encrypt(g_plain[i]);
    }
  }
}

static void PaillierAddCipher(benchmark::State& state) {
  // add (ciphertext + ciphertext)
  paillier_f::Evaluator evaluator(g_paillier_public_key);
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator.AddInplace(&g_paillier_ciphertext[0], g_paillier_ciphertext[i]);
    }
  }
}

static void PaillierAddInt(benchmark::State& state) {
  // add (ciphertext + plaintext)
  paillier_f::Evaluator evaluator(g_paillier_public_key);
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator.AddInplace(&g_paillier_ciphertext[i], MPInt(i));
    }
  }
}

static void PaillierMulti(benchmark::State& state) {
  // mul (ciphertext * plaintext)
  paillier_f::Evaluator evaluator(g_paillier_public_key);
  for (auto _ : state) {
    for (int i = 1; i < kTestSize; ++i) {
      evaluator.MulInplace(&g_paillier_ciphertext[i], MPInt(i));
    }
  }
}

static void PaillierDecrypt(benchmark::State& state) {
  // decrypt
  paillier_f::Decryptor decryptor(g_paillier_public_key, g_paillier_secret_key);
  for (auto _ : state) {
    for (int i = 0; i < kTestSize; ++i) {
      decryptor.Decrypt(g_paillier_ciphertext[i], g_plain + i);
    }
  }
}

BENCHMARK(PaillierEncrypt)->Unit(benchmark::kMillisecond);
BENCHMARK(PaillierAddCipher)->Unit(benchmark::kMillisecond);
BENCHMARK(PaillierAddInt)->Unit(benchmark::kMillisecond);
BENCHMARK(PaillierMulti)->Unit(benchmark::kMillisecond);
BENCHMARK(PaillierDecrypt)->Unit(benchmark::kMillisecond);
}  // namespace heu::lib::phe::bench

int main(int argc, char** argv) {
  benchmark::Initialize(&argc, argv);
  heu::lib::phe::bench::Initialize();
  benchmark::RunSpecifiedBenchmarks();
  return 0;
}
