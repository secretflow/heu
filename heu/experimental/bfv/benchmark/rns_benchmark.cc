#include <benchmark/benchmark.h>

#include <cstdint>
#include <memory>
#include <random>
#include <stdexcept>

#include "math/biguint.h"
#include "math/primes.h"
#include "math/residue_transfer_engine.h"
#include "math/rns_context.h"
#include "math/scaling_factor.h"

using namespace bfv::math::rns;

namespace {

std::vector<uint64_t> BuildBenchmarkBasis(size_t count, uint64_t tag) {
  std::vector<uint64_t> basis;
  basis.reserve(count);
  uint64_t upper_bound = (uint64_t{1} << 62) - 1 - (tag % 257);
  for (size_t idx = 0; idx < count; ++idx) {
    auto prime = ::bfv::math::zq::generate_prime(62, 2, upper_bound);
    if (!prime.has_value()) {
      throw std::runtime_error("Failed to generate benchmark residue basis");
    }
    basis.push_back(*prime);
    upper_bound = *prime - 2 - ((tag + idx) % 5);
  }
  return basis;
}

const std::vector<uint64_t> &SourceBenchmarkBasis() {
  static const std::vector<uint64_t> basis =
      BuildBenchmarkBasis(3, 0x71736f75726365ULL);
  return basis;
}

const std::vector<uint64_t> &TargetBenchmarkBasis() {
  static const std::vector<uint64_t> basis =
      BuildBenchmarkBasis(4, 0x747267745f6261ULL);
  return basis;
}

}  // namespace

class RnsBenchmarkFixture : public benchmark::Fixture {
 public:
  void SetUp(const benchmark::State &state) override {
    rns_q = RnsContext::create(SourceBenchmarkBasis());
    rns_p = RnsContext::create(TargetBenchmarkBasis());

    // Using simplified scaling factor creation without BigUint dependency
    ScalingFactor scaling_factor = ScalingFactor::one();
    transfer_engine =
        std::make_unique<ResidueTransferEngine>(rns_q, rns_p, scaling_factor);

    ScalingFactor one_factor = ScalingFactor::one();
    transfer_engine_as_converter =
        std::make_unique<ResidueTransferEngine>(rns_q, rns_p, one_factor);

    std::mt19937_64 rng(42);  // Fixed seed for reproducibility
    x.resize(SourceBenchmarkBasis().size());
    for (size_t i = 0; i < SourceBenchmarkBasis().size(); ++i) {
      x[i] = rng() % SourceBenchmarkBasis()[i];
    }

    // Prepare output vector
    y.resize(TargetBenchmarkBasis().size());
  }

 protected:
  std::shared_ptr<RnsContext> rns_q;
  std::shared_ptr<RnsContext> rns_p;
  std::unique_ptr<ResidueTransferEngine> transfer_engine;
  std::unique_ptr<ResidueTransferEngine> transfer_engine_as_converter;
  std::vector<uint64_t> x;
  std::vector<uint64_t> y;
};

BENCHMARK_DEFINE_F(RnsBenchmarkFixture, BasisTransferRoute)
(benchmark::State &state) {
  for (auto _ : state) {
    transfer_engine->scale(x, y, 0);
    benchmark::DoNotOptimize(y);
  }
}

BENCHMARK_DEFINE_F(RnsBenchmarkFixture, TransferAsConverter)
(benchmark::State &state) {
  for (auto _ : state) {
    transfer_engine_as_converter->scale(x, y, 0);
    benchmark::DoNotOptimize(y);
  }
}

// Register benchmarks with the same parameters
void RegisterRnsBenchmarks() {
  std::string suffix = std::to_string(SourceBenchmarkBasis().size()) + "->" +
                       std::to_string(TargetBenchmarkBasis().size());

  BENCHMARK_REGISTER_F(RnsBenchmarkFixture, BasisTransferRoute)
      ->Name("rns/transfer_engine/" + suffix)
      ->Iterations(50);

  BENCHMARK_REGISTER_F(RnsBenchmarkFixture, TransferAsConverter)
      ->Name("rns/transfer_engine_as_converter/" + suffix)
      ->Iterations(50);
}

// Call the registration function
static bool registered = []() {
  RegisterRnsBenchmarks();
  return true;
}();

BENCHMARK_MAIN();
