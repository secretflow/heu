#include <benchmark/benchmark.h>

#include <iostream>
#include <optional>
#include <random>

#include "math/modulus.h"
#include "math/ntt.h"

using namespace bfv::math::ntt;
using namespace bfv::math::zq;

static const std::vector<size_t> VECTOR_SIZES = {1024, 4096};
static const std::vector<uint64_t> MODULI = {4611686018326724609ULL, 40961ULL};

class NttBenchmarkFixture : public benchmark::Fixture {
 public:
  void SetUp(benchmark::State &state) override {
    vector_size = state.range(0);
    modulus_value = state.range(1);

    auto modulus_opt = Modulus::New(modulus_value);
    if (!modulus_opt) {
      state.SkipWithError("Failed to create modulus");
      return;
    }
    modulus_.emplace(std::move(*modulus_opt));

    auto op_opt = NttOperator::New(*modulus_, vector_size);
    if (!op_opt) {
      state.SkipWithError("Failed to create NTT operator");
      return;
    }
    ntt_op_.emplace(std::move(*op_opt));

    std::mt19937_64 rng;
    data.resize(vector_size);
    for (size_t i = 0; i < vector_size; ++i) {
      data[i] = modulus_->Reduce(rng());
    }
  }

 protected:
  size_t vector_size;
  uint64_t modulus_value;
  std::optional<Modulus> modulus_;
  std::optional<NttOperator> ntt_op_;
  std::vector<uint64_t> data;
};

BENCHMARK_DEFINE_F(NttBenchmarkFixture, Forward)(benchmark::State &state) {
  for (auto _ : state) {
    auto data_copy = data;
    auto result = ntt_op_->Forward(data_copy);
    benchmark::DoNotOptimize(result);
  }
}

BENCHMARK_DEFINE_F(NttBenchmarkFixture, ForwardVt)(benchmark::State &state) {
  for (auto _ : state) {
    auto data_copy = data;
    auto result = ntt_op_->ForwardVt(data_copy);
    benchmark::DoNotOptimize(result);
  }
}

BENCHMARK_DEFINE_F(NttBenchmarkFixture, Backward)(benchmark::State &state) {
  for (auto _ : state) {
    auto data_copy = data;
    auto result = ntt_op_->Backward(data_copy);
    benchmark::DoNotOptimize(result);
  }
}

BENCHMARK_DEFINE_F(NttBenchmarkFixture, BackwardVt)(benchmark::State &state) {
  for (auto _ : state) {
    auto data_copy = data;
    auto result = ntt_op_->BackwardVt(data_copy);
    benchmark::DoNotOptimize(result);
  }
}

// Register benchmarks with the same parameters
void RegisterNttBenchmarks() {
  for (size_t vector_size : VECTOR_SIZES) {
    for (uint64_t modulus : MODULI) {
      uint32_t p_nbits = 64 - __builtin_clzll(modulus);
      std::string suffix =
          std::to_string(vector_size) + "/" + std::to_string(p_nbits);
      // debug removed

      std::string name_forward = std::string("ntt/forward/") +
                                 std::to_string(vector_size) + "/" +
                                 std::to_string(modulus);
      std::string name_forward_vt = std::string("ntt/forward_vt/") +
                                    std::to_string(vector_size) + "/" +
                                    std::to_string(modulus);
      std::string name_backward = std::string("ntt/backward/") +
                                  std::to_string(vector_size) + "/" +
                                  std::to_string(modulus);
      std::string name_backward_vt = std::string("ntt/backward_vt/") +
                                     std::to_string(vector_size) + "/" +
                                     std::to_string(modulus);

      BENCHMARK_REGISTER_F(NttBenchmarkFixture, Forward)
          ->Args({static_cast<int64_t>(vector_size),
                  static_cast<int64_t>(modulus)})
          ->Name(name_forward)
          ->Iterations(50);

      BENCHMARK_REGISTER_F(NttBenchmarkFixture, ForwardVt)
          ->Args({static_cast<int64_t>(vector_size),
                  static_cast<int64_t>(modulus)})
          ->Name(name_forward_vt)
          ->Iterations(50);

      BENCHMARK_REGISTER_F(NttBenchmarkFixture, Backward)
          ->Args({static_cast<int64_t>(vector_size),
                  static_cast<int64_t>(modulus)})
          ->Name(name_backward)
          ->Iterations(50);

      BENCHMARK_REGISTER_F(NttBenchmarkFixture, BackwardVt)
          ->Args({static_cast<int64_t>(vector_size),
                  static_cast<int64_t>(modulus)})
          ->Name(name_backward_vt)
          ->Iterations(50);
    }
  }

  // Explicitly ensure 4096/40961 registrations present
  const int64_t kN = 4096;
  const int64_t kP = 40961;
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, Forward)
      ->Args({kN, kP})
      ->Name("ntt/forward/4096/40961")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, ForwardVt)
      ->Args({kN, kP})
      ->Name("ntt/forward_vt/4096/40961")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, Backward)
      ->Args({kN, kP})
      ->Name("ntt/backward/4096/40961")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, BackwardVt)
      ->Args({kN, kP})
      ->Name("ntt/backward_vt/4096/40961")
      ->Iterations(50);

  // Also explicitly ensure 1024/40961 registrations present
  const int64_t kN1 = 1024;
  const int64_t kP1 = 40961;
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, Forward)
      ->Args({kN1, kP1})
      ->Name("ntt/forward/1024/40961")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, ForwardVt)
      ->Args({kN1, kP1})
      ->Name("ntt/forward_vt/1024/40961")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, Backward)
      ->Args({kN1, kP1})
      ->Name("ntt/backward/1024/40961")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, BackwardVt)
      ->Args({kN1, kP1})
      ->Name("ntt/backward_vt/1024/40961")
      ->Iterations(50);

  // And explicitly ensure 4096/4611686018326724609 registrations present
  const int64_t kN2 = 4096;
  const long long kP2 = 4611686018326724609LL;
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, Forward)
      ->Args({kN2, static_cast<int64_t>(kP2)})
      ->Name("ntt/forward/4096/4611686018326724609")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, ForwardVt)
      ->Args({kN2, static_cast<int64_t>(kP2)})
      ->Name("ntt/forward_vt/4096/4611686018326724609")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, Backward)
      ->Args({kN2, static_cast<int64_t>(kP2)})
      ->Name("ntt/backward/4096/4611686018326724609")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(NttBenchmarkFixture, BackwardVt)
      ->Args({kN2, static_cast<int64_t>(kP2)})
      ->Name("ntt/backward_vt/4096/4611686018326724609")
      ->Iterations(50);
}

// Call the registration function
static bool registered = []() {
  RegisterNttBenchmarks();
  return true;
}();

BENCHMARK_MAIN();
