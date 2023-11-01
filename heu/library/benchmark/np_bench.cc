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

#include "heu/library/numpy/numpy.h"
#include "heu/library/phe/encoding/encoding.h"

namespace heu::lib::bench {

constexpr int kRandomScale = 8011;

class NpBenchmarks {
 public:
  numpy::PMatrix GenMatrix(const numpy::Shape &s) {
    auto edr = he_kit_->GetEncoder<phe::PlainEncoder>(kRandomScale);
    numpy::PMatrix res(s);
    res.ForEach([this, &edr](int64_t /*row*/, int64_t /*col*/,
                             phe::Plaintext *element) {
      // 'counter' do not need to be locked
      *element = edr.Encode(++counter);
    });
    return res;
  }

  void SetupAndRegister(phe::SchemaType schema_type, int key_size) {
    he_kit_ = std::make_unique<numpy::HeKit>(phe::HeKit(schema_type, key_size));
    pt_matrixs_.push_back(GenMatrix({2048, 101}));
    pt_matrixs_.push_back(GenMatrix({101}));
    pt_matrixs_.push_back(GenMatrix({2048}));
    pt_matrixs_.push_back(GenMatrix({512, 512}));
    ct_matrixs_1_.push_back(numpy::CMatrix(1));  // placeholder
    ct_matrixs_1_.push_back(numpy::CMatrix(1));
    ct_matrixs_1_.push_back(numpy::CMatrix(1));
    ct_matrixs_1_.push_back(numpy::CMatrix(1));
    ct_matrixs_2_.push_back(numpy::CMatrix(1));  // placeholder
    ct_matrixs_2_.push_back(numpy::CMatrix(1));
    ct_matrixs_2_.push_back(numpy::CMatrix(1));
    ct_matrixs_2_.push_back(numpy::CMatrix(1));

    // register
    for (size_t i = 0; i < pt_matrixs_.size(); ++i) {
      benchmark::RegisterBenchmark(
          fmt::format("{:^9}|Encrypt(shape={})", he_kit_->GetSchemaType(),
                      pt_matrixs_[i].shape().ToString())
              .c_str(),
          [this, i](benchmark::State &st) { Encrypt(st, i); })
          ->Unit(benchmark::kMillisecond);
    }
    for (size_t i = 0; i < pt_matrixs_.size(); ++i) {
      benchmark::RegisterBenchmark(
          fmt::format("{:^9}|AddCipher(shape={})", he_kit_->GetSchemaType(),
                      pt_matrixs_[i].shape().ToString())
              .c_str(),
          [this, i](benchmark::State &st) { AddCipher(st, i); })
          ->Unit(benchmark::kMillisecond);
    }
    for (size_t i = 0; i < pt_matrixs_.size(); ++i) {
      benchmark::RegisterBenchmark(
          fmt::format("{:^9}|SubCipher(shape={})", he_kit_->GetSchemaType(),
                      pt_matrixs_[i].shape().ToString())
              .c_str(),
          [this, i](benchmark::State &st) { SubCipher(st, i); })
          ->Unit(benchmark::kMillisecond);
    }
    for (size_t i = 0; i < pt_matrixs_.size(); ++i) {
      benchmark::RegisterBenchmark(
          fmt::format("{:^9}|AddInt(shape={})", he_kit_->GetSchemaType(),
                      pt_matrixs_[i].shape().ToString())
              .c_str(),
          [this, i](benchmark::State &st) { AddInt(st, i); })
          ->Unit(benchmark::kMillisecond);
    }
    for (size_t i = 0; i < pt_matrixs_.size(); ++i) {
      benchmark::RegisterBenchmark(
          fmt::format("{:^9}|SubInt(shape={})", he_kit_->GetSchemaType(),
                      pt_matrixs_[i].shape().ToString())
              .c_str(),
          [this, i](benchmark::State &st) { SubInt(st, i); })
          ->Unit(benchmark::kMillisecond);
    }
    std::vector<std::pair<int, int>> cases = {{0, 1}, {2, 0}, {3, 3}};
    for (const auto &c : cases) {
      benchmark::RegisterBenchmark(
          fmt::format("{:^9}|Matmul({}@{})", he_kit_->GetSchemaType(),
                      pt_matrixs_[c.first].shape().ToString(),
                      pt_matrixs_[c.second].shape().ToString())
              .c_str(),
          [this, c](benchmark::State &st) { Matmul(st, c.first, c.second); })
          ->Unit(benchmark::kMillisecond);
    }
    for (size_t i = 0; i < pt_matrixs_.size(); ++i) {
      benchmark::RegisterBenchmark(
          fmt::format("{:^9}|Mul(shape={})", he_kit_->GetSchemaType(),
                      pt_matrixs_[i].shape().ToString())
              .c_str(),
          [this, i](benchmark::State &st) { Mul(st, i); })
          ->Unit(benchmark::kMillisecond);
    }
    for (size_t i = 0; i < pt_matrixs_.size(); ++i) {
      benchmark::RegisterBenchmark(
          fmt::format("{:^9}|Decrypt(shape={})", he_kit_->GetSchemaType(),
                      pt_matrixs_[i].shape().ToString())
              .c_str(),
          [this, i](benchmark::State &st) { Decrypt(st, i); })
          ->Unit(benchmark::kMillisecond);
    }
  }

  void Encrypt(benchmark::State &state, size_t idx) {
    std::call_once(flag_, []() { fmt::print("{:-^80}\n", ""); });
    // encrypt
    const auto &encryptor = he_kit_->GetEncryptor();
    for (auto _ : state) {
      ct_matrixs_1_[idx] = encryptor->Encrypt(pt_matrixs_[idx]);
    }
  }

  void AddCipher(benchmark::State &state, size_t idx) {
    // add (ciphertext + ciphertext)
    const auto &evaluator = he_kit_->GetEvaluator();
    for (auto _ : state) {
      ct_matrixs_2_[idx] =
          evaluator->Add(ct_matrixs_1_[idx], ct_matrixs_1_[idx]);
    }
  }

  void SubCipher(benchmark::State &state, size_t idx) {
    // sub (ciphertext - ciphertext)
    const auto &evaluator = he_kit_->GetEvaluator();
    for (auto _ : state) {
      ct_matrixs_2_[idx] =
          evaluator->Sub(ct_matrixs_2_[idx], ct_matrixs_1_[idx]);
    }
  }

  void AddInt(benchmark::State &state, size_t idx) {
    // add (ciphertext + plaintext)
    const auto &evaluator = he_kit_->GetEvaluator();
    for (auto _ : state) {
      ct_matrixs_2_[idx] = evaluator->Add(ct_matrixs_1_[idx], pt_matrixs_[idx]);
    }
  }

  void SubInt(benchmark::State &state, size_t idx) {
    // add (ciphertext - plaintext)
    const auto &evaluator = he_kit_->GetEvaluator();
    for (auto _ : state) {
      ct_matrixs_2_[idx] = evaluator->Sub(ct_matrixs_1_[idx], pt_matrixs_[idx]);
    }
  }

  void Matmul(benchmark::State &state, size_t i1, size_t i2) {
    // mul (ciphertext * plaintext)
    const auto &evaluator = he_kit_->GetEvaluator();
    for (auto _ : state) {
      benchmark::DoNotOptimize(
          evaluator->MatMul(ct_matrixs_1_[i1], pt_matrixs_[i2]));
    }
  }

  void Mul(benchmark::State &state, size_t i) {
    const auto &evaluator = he_kit_->GetEvaluator();
    for (auto _ : state) {
      benchmark::DoNotOptimize(
          evaluator->Mul(ct_matrixs_1_[i], pt_matrixs_[i]));
    }
  }

  void Decrypt(benchmark::State &state, size_t idx) {
    // decrypt
    const auto &decryptor = he_kit_->GetDecryptor();
    for (auto _ : state) {
      pt_matrixs_[idx] = decryptor->Decrypt(ct_matrixs_1_[idx]);
    }
  }

 private:
  int64_t counter = 0;
  std::once_flag flag_;
  std::unique_ptr<numpy::HeKit> he_kit_;
  std::vector<numpy::PMatrix> pt_matrixs_;
  std::vector<numpy::CMatrix> ct_matrixs_1_;
  std::vector<numpy::CMatrix> ct_matrixs_2_;
};

}  // namespace heu::lib::bench

DEFINE_string(schema, ".+", "Run selected schemas, default to all.");
DEFINE_int32(key_size, 2048, "Key size of phe schema.");

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  benchmark::Initialize(&argc, argv);
  benchmark::AddCustomContext("Key size", fmt::format("{}", FLAGS_key_size));

  auto schemas = heu::lib::phe::SelectSchemas(FLAGS_schema);
  fmt::print("Schemas to bench: {}\n", schemas);
  std::vector<heu::lib::bench::NpBenchmarks> bms(schemas.size());
  for (size_t i = 0; i < schemas.size(); ++i) {
    bms[i].SetupAndRegister(schemas[i], FLAGS_key_size);
  }

  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  return 0;
}
