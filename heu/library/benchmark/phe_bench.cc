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
#include <mutex>

#include "benchmark/benchmark.h"
#include "fmt/ranges.h"
#include "gflags/gflags.h"

#include "heu/library/phe/encoding/encoding.h"
#include "heu/library/phe/phe.h"

namespace heu::lib::bench {

constexpr static long kTestSize = 10000;
constexpr int kRandomScale = 8011;

class PheBenchmarks {
 public:
  void SetupAndRegister(phe::SchemaType schema_type, int key_size) {
    he_kit_ = std::make_unique<phe::HeKit>(schema_type, key_size);
    auto edr = he_kit_->GetEncoder<phe::PlainEncoder>(kRandomScale);
    for (int i = 0; i < kTestSize; ++i) {
      pts_[i] = edr.Encode(i);
    }

    benchmark::RegisterBenchmark(
        fmt::format("{:^9}|Encrypt", he_kit_->GetSchemaType()).c_str(),
        [this](benchmark::State& st) { Encrypt(st); })
        ->Unit(benchmark::kMillisecond);
    benchmark::RegisterBenchmark(
        fmt::format("{:^9}|CT+CT", he_kit_->GetSchemaType()).c_str(),
        [this](benchmark::State& st) { AddCipher(st); })
        ->Unit(benchmark::kMillisecond);
    benchmark::RegisterBenchmark(
        fmt::format("{:^9}|CT-CT", he_kit_->GetSchemaType()).c_str(),
        [this](benchmark::State& st) { SubCipher(st); })
        ->Unit(benchmark::kMillisecond);
    benchmark::RegisterBenchmark(
        fmt::format("{:^9}|CT+PT", he_kit_->GetSchemaType()).c_str(),
        [this](benchmark::State& st) { AddInt(st); })
        ->Unit(benchmark::kMillisecond);
    benchmark::RegisterBenchmark(
        fmt::format("{:^9}|CT-PT", he_kit_->GetSchemaType()).c_str(),
        [this](benchmark::State& st) { SubInt(st); })
        ->Unit(benchmark::kMillisecond);
    benchmark::RegisterBenchmark(
        fmt::format("{:^9}|CT*PT", he_kit_->GetSchemaType()).c_str(),
        [this](benchmark::State& st) { Multi(st); })
        ->Unit(benchmark::kMillisecond);
    benchmark::RegisterBenchmark(
        fmt::format("{:^9}|Decrypt", he_kit_->GetSchemaType()).c_str(),
        [this](benchmark::State& st) { Decrypt(st); })
        ->Unit(benchmark::kMillisecond);
  }

  void Encrypt(benchmark::State& state) {
    std::call_once(flag_, []() { fmt::print("{:-^62}\n", ""); });

    // encrypt
    const auto& encryptor = he_kit_->GetEncryptor();
    for (auto _ : state) {
      for (int i = 0; i < kTestSize; ++i) {
        *(cts_ + i) = encryptor->Encrypt(pts_[i]);
      }
    }
  }

  void AddCipher(benchmark::State& state) {
    // add (ciphertext + ciphertext)
    const auto& evaluator = he_kit_->GetEvaluator();
    auto ct = he_kit_->GetEncryptor()->EncryptZero();
    for (auto _ : state) {
      for (int i = 0; i < kTestSize; ++i) {
        evaluator->AddInplace(&ct, cts_[i]);
      }
    }
  }

  void SubCipher(benchmark::State& state) {
    // sub (ciphertext - ciphertext)
    const auto& evaluator = he_kit_->GetEvaluator();
    auto ct = he_kit_->GetEncryptor()->EncryptZero();
    for (auto _ : state) {
      for (int i = 0; i < kTestSize; ++i) {
        evaluator->SubInplace(&ct, cts_[i]);
      }
    }
  }

  void AddInt(benchmark::State& state) {
    // add (ciphertext + plaintext)
    const auto& evaluator = he_kit_->GetEvaluator();
    auto edr = he_kit_->GetEncoder<phe::PlainEncoder>(1);
    for (auto _ : state) {
      for (int i = 0; i < kTestSize; ++i) {
        evaluator->AddInplace(&cts_[i], edr.Encode(i));
      }
    }
  }

  void SubInt(benchmark::State& state) {
    // add (ciphertext - plaintext)
    const auto& evaluator = he_kit_->GetEvaluator();
    auto edr = he_kit_->GetEncoder<phe::PlainEncoder>(1);
    for (auto _ : state) {
      for (int i = 0; i < kTestSize; ++i) {
        evaluator->SubInplace(&cts_[i], edr.Encode(i));
      }
    }
  }

  void Multi(benchmark::State& state) {
    // mul (ciphertext * plaintext)
    const auto& evaluator = he_kit_->GetEvaluator();
    auto edr = he_kit_->GetEncoder<phe::PlainEncoder>(1);
    auto ct = he_kit_->GetEncryptor()->Encrypt(edr.Encode(1));
    for (auto _ : state) {
      for (int i = 1; i < kTestSize; ++i) {
        evaluator->MulInplace(&ct, edr.Encode(i));
      }
    }
  }

  void Decrypt(benchmark::State& state) {
    // decrypt
    const auto& decryptor = he_kit_->GetDecryptor();
    for (auto _ : state) {
      for (int i = 0; i < kTestSize; ++i) {
        decryptor->Decrypt(cts_[i], pts_ + i);
      }
    }
  }

 private:
  std::once_flag flag_;
  std::unique_ptr<phe::HeKit> he_kit_;
  phe::Plaintext pts_[kTestSize];
  phe::Ciphertext cts_[kTestSize];
};

}  // namespace heu::lib::bench

DEFINE_string(schema, ".+", "Run selected schemas, default to all.");
DEFINE_int32(key_size, 2048, "Key size of phe schema.");

int main(int argc, char** argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  benchmark::Initialize(&argc, argv);
  benchmark::AddCustomContext("Run times",
                              fmt::format("{}", heu::lib::bench::kTestSize));
  benchmark::AddCustomContext("Key size", fmt::format("{}", FLAGS_key_size));

  auto schemas = heu::lib::phe::SelectSchemas(FLAGS_schema);
  fmt::print("Schemas to bench: {}\n", schemas);
  std::vector<heu::lib::bench::PheBenchmarks> bms(schemas.size());
  for (size_t i = 0; i < schemas.size(); ++i) {
    bms[i].SetupAndRegister(schemas[i], FLAGS_key_size);
  }

  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  return 0;
}
