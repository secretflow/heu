#include <benchmark/benchmark.h>

#include <memory>
#include <optional>
#include <random>
#include <vector>

#include "math/context.h"
#include "math/poly.h"
#include "math/representation.h"

using namespace bfv::math::rq;

static const std::vector<uint64_t> MODULI = {
    562949954093057ULL,
    4611686018326724609ULL,
    4611686018309947393ULL,
    4611686018282684417ULL,
};

static const std::vector<size_t> DEGREES = {1024, 2048, 4096, 8192};

class RqBenchmarkFixture {
 public:
  void SetUp(size_t degree_param, bool use_vt_param) {
    degree = degree_param;
    use_vt = use_vt_param;

    std::vector<uint64_t> single_modulus = {MODULI[0]};
    ctx = Context::create(single_modulus, degree);

    // Generate random polynomials
    std::mt19937_64 rng;
    p_.emplace(Poly::random(ctx, Representation::Ntt, rng));
    q_.emplace(Poly::random(ctx, Representation::Ntt, rng));

    if (use_vt) {
      q_->allow_variable_time_computations();
    }
  }

  const Poly &GetP() const { return *p_; }

  const Poly &GetQ() const { return *q_; }

 protected:
  size_t degree;
  bool use_vt;
  std::shared_ptr<const Context> ctx;
  std::optional<Poly> p_;
  std::optional<Poly> q_;
};

// Benchmark functions are now defined inline in RegisterRqBenchmarks()

// Register benchmarks
void RegisterRqBenchmarks() {
  for (size_t degree : DEGREES) {
    for (int use_vt : {0, 1}) {
      std::string suffix =
          std::to_string(degree) + "/" + (use_vt ? "vt" : "ct");

      // Basic operations
      benchmark::RegisterBenchmark("rq/add/" + suffix,
                                   [degree, use_vt](benchmark::State &state) {
                                     RqBenchmarkFixture fixture;
                                     fixture.SetUp(degree, use_vt);
                                     for (auto _ : state) {
                                       auto result =
                                           fixture.GetP() + fixture.GetQ();
                                       benchmark::DoNotOptimize(result);
                                     }
                                   })
          ->Iterations(50);

      benchmark::RegisterBenchmark(
          "rq/add_assign/" + suffix,
          [degree, use_vt](benchmark::State &state) {
            RqBenchmarkFixture fixture;
            fixture.SetUp(degree, use_vt);
            auto p_copy = fixture.GetP();  // Create copy once outside the loop
            for (auto _ : state) {
              p_copy += fixture.GetQ();
              benchmark::DoNotOptimize(p_copy);
            }
          })
          ->Iterations(50);

      benchmark::RegisterBenchmark("rq/sub/" + suffix,
                                   [degree, use_vt](benchmark::State &state) {
                                     RqBenchmarkFixture fixture;
                                     fixture.SetUp(degree, use_vt);
                                     for (auto _ : state) {
                                       auto result =
                                           fixture.GetP() - fixture.GetQ();
                                       benchmark::DoNotOptimize(result);
                                     }
                                   })
          ->Iterations(50);

      benchmark::RegisterBenchmark(
          "rq/sub_assign/" + suffix,
          [degree, use_vt](benchmark::State &state) {
            RqBenchmarkFixture fixture;
            fixture.SetUp(degree, use_vt);
            auto p_copy = fixture.GetP();  // Create copy once outside the loop
            for (auto _ : state) {
              p_copy -= fixture.GetQ();
              benchmark::DoNotOptimize(p_copy);
            }
          })
          ->Iterations(50);

      benchmark::RegisterBenchmark("rq/mul/" + suffix,
                                   [degree, use_vt](benchmark::State &state) {
                                     RqBenchmarkFixture fixture;
                                     fixture.SetUp(degree, use_vt);
                                     for (auto _ : state) {
                                       auto result =
                                           fixture.GetP() * fixture.GetQ();
                                       benchmark::DoNotOptimize(result);
                                     }
                                   })
          ->Iterations(50);

      benchmark::RegisterBenchmark(
          "rq/mul_assign/" + suffix,
          [degree, use_vt](benchmark::State &state) {
            RqBenchmarkFixture fixture;
            fixture.SetUp(degree, use_vt);
            auto p_copy = fixture.GetP();  // Create copy once outside the loop
            for (auto _ : state) {
              p_copy *= fixture.GetQ();
              benchmark::DoNotOptimize(p_copy);
            }
          })
          ->Iterations(50);

      benchmark::RegisterBenchmark("rq/neg/" + suffix,
                                   [degree, use_vt](benchmark::State &state) {
                                     RqBenchmarkFixture fixture;
                                     fixture.SetUp(degree, use_vt);
                                     for (auto _ : state) {
                                       auto result = -fixture.GetP();
                                       benchmark::DoNotOptimize(result);
                                     }
                                   })
          ->Iterations(50);
    }
  }

  // Multi-modulus benchmarks
  for (size_t degree : DEGREES) {
    for (size_t num_moduli : {1, 2, 4}) {
      if (num_moduli > MODULI.size()) continue;

      std::vector<uint64_t> moduli(MODULI.begin(), MODULI.begin() + num_moduli);
      std::string suffix =
          std::to_string(degree) + "/" + std::to_string(num_moduli) + "mod";

      benchmark::RegisterBenchmark(
          "rq/mul_multimod/" + suffix,
          [degree, moduli](benchmark::State &state) {
            auto ctx = Context::create(moduli, degree);
            std::mt19937_64 rng;
            auto p = Poly::random(ctx, Representation::Ntt, rng);
            auto q = Poly::random(ctx, Representation::Ntt, rng);

            for (auto _ : state) {
              auto result = p * q;
              benchmark::DoNotOptimize(result);
            }
          })
          ->Iterations(50);

      // Representation change benchmarks
      benchmark::RegisterBenchmark(
          "rq/change_repr_to_ntt/" + suffix,
          [degree, moduli](benchmark::State &state) {
            auto ctx = Context::create(moduli, degree);
            std::mt19937_64 rng;
            auto p = Poly::random(ctx, Representation::PowerBasis, rng);

            for (auto _ : state) {
              auto p_copy = p;
              p_copy.change_representation(Representation::Ntt);
              benchmark::DoNotOptimize(p_copy);
            }
          })
          ->Iterations(50);

      benchmark::RegisterBenchmark(
          "rq/change_repr_to_power/" + suffix,
          [degree, moduli](benchmark::State &state) {
            auto ctx = Context::create(moduli, degree);
            std::mt19937_64 rng;
            auto p = Poly::random(ctx, Representation::Ntt, rng);

            for (auto _ : state) {
              auto p_copy = p;
              p_copy.change_representation(Representation::PowerBasis);
              benchmark::DoNotOptimize(p_copy);
            }
          })
          ->Iterations(50);
    }
  }
}

// Call the registration function
static bool registered = []() {
  RegisterRqBenchmarks();
  return true;
}();

BENCHMARK_MAIN();
