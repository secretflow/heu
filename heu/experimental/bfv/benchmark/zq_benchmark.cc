#include <benchmark/benchmark.h>

#include <optional>
#include <random>

#include "math/modulus.h"

using namespace bfv::math::zq;

static const uint64_t MODULUS_VALUE = 4611686018326724609ULL;
static const std::vector<size_t> VECTOR_SIZES = {1024, 4096};

class ZqBenchmarkFixture : public benchmark::Fixture {
 public:
  void SetUp(benchmark::State &state) override {
    vector_size = state.range(0);

    auto modulus_opt = Modulus::New(MODULUS_VALUE);
    if (!modulus_opt) {
      state.SkipWithError("Failed to create modulus");
      return;
    }
    modulus_.emplace(std::move(*modulus_opt));

    std::mt19937_64 rng;
    a.resize(vector_size);
    c.resize(vector_size);
    c_shoup.resize(vector_size);
    c_precomp.resize(vector_size);

    for (size_t i = 0; i < vector_size; ++i) {
      a[i] = modulus_->Reduce(rng());
      c[i] = modulus_->Reduce(rng());
      c_shoup[i] = modulus_->Shoup(c[i]);
      c_precomp[i] = modulus_->PrepareMultiplyOperand(c[i]);
    }

    scalar = c[0];
  }

 protected:
  size_t vector_size;
  std::optional<Modulus> modulus_;
  std::vector<uint64_t> a;
  std::vector<uint64_t> c;
  std::vector<uint64_t> c_shoup;
  std::vector<MultiplyUIntModOperand> c_precomp;
  uint64_t scalar;
};

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, AddVec)(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->AddVec(a_copy, c);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, AddVecVt)(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->AddVecVt(a_copy, c);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, SubVec)(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->SubVec(a_copy, c);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, NegVec)(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->NegVec(a_copy);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, MulVec)(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->MulVec(a_copy, c);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, MulVecVt)(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->MulVecVt(a_copy, c);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, MulOptimizedVec)
(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->MulOptimizedVec(a_copy, c_precomp);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, MulOptimizedVecLazy)
(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->MulOptimizedVecLazy(a_copy, c_precomp);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, MulShoupVec)(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->MulShoupVec(a_copy, c, c_shoup);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, ScalarMulVec)(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->ScalarMulVec(a_copy, scalar);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, MulShoupVecVt)(benchmark::State &state) {
  for (auto _ : state) {
    auto a_copy = a;
    modulus_->MulShoupVecVt(a_copy, c, c_shoup);
    benchmark::DoNotOptimize(a_copy);
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, ReduceU128)(benchmark::State &state) {
  // Generate 128-bit test values
  std::mt19937_64 rng;
  std::vector<__uint128_t> test_values(vector_size);
  for (size_t i = 0; i < vector_size; ++i) {
    test_values[i] = ((__uint128_t)rng() << 64) | rng();
  }

  for (auto _ : state) {
    for (size_t i = 0; i < vector_size; ++i) {
      uint64_t result = modulus_->ReduceU128(test_values[i]);
      benchmark::DoNotOptimize(result);
    }
  }
}

BENCHMARK_DEFINE_F(ZqBenchmarkFixture, LazyMulShoup)(benchmark::State &state) {
  for (auto _ : state) {
    for (size_t i = 0; i < vector_size; ++i) {
      uint64_t result = modulus_->LazyMulShoup(a[i], c[i], c_shoup[i]);
      benchmark::DoNotOptimize(result);
    }
  }
}

// Register benchmarks
void RegisterZqBenchmarks() {
  for (size_t vector_size : VECTOR_SIZES) {
    std::string suffix = std::to_string(vector_size);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, AddVec)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/add_vec/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, AddVecVt)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/add_vec_vt/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, SubVec)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/sub_vec/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, NegVec)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/neg_vec/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulVec)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/mul_vec/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulVecVt)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/mul_vec_vt/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulOptimizedVec)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/mul_optimized_vec/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulOptimizedVecLazy)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/mul_optimized_vec_lazy/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulShoupVec)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/mul_shoup_vec/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, ScalarMulVec)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/scalar_mul_vec/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulShoupVecVt)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/mul_shoup_vec_vt/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, ReduceU128)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/reduce_u128/" + suffix)
        ->Iterations(50);

    BENCHMARK_REGISTER_F(ZqBenchmarkFixture, LazyMulShoup)
        ->Args({static_cast<int64_t>(vector_size)})
        ->Name("zq/lazy_mul_shoup/" + suffix)
        ->Iterations(50);
  }

  // Explicitly ensure 4096 registrations present (workaround for missing
  // entries in some builds)
  const int64_t kN = 4096;
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, AddVec)
      ->Args({kN})
      ->Name("zq/add_vec/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, AddVecVt)
      ->Args({kN})
      ->Name("zq/add_vec_vt/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, SubVec)
      ->Args({kN})
      ->Name("zq/sub_vec/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, NegVec)
      ->Args({kN})
      ->Name("zq/neg_vec/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulVec)
      ->Args({kN})
      ->Name("zq/mul_vec/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulVecVt)
      ->Args({kN})
      ->Name("zq/mul_vec_vt/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulOptimizedVec)
      ->Args({kN})
      ->Name("zq/mul_optimized_vec/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulOptimizedVecLazy)
      ->Args({kN})
      ->Name("zq/mul_optimized_vec_lazy/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulShoupVec)
      ->Args({kN})
      ->Name("zq/mul_shoup_vec/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, ScalarMulVec)
      ->Args({kN})
      ->Name("zq/scalar_mul_vec/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, MulShoupVecVt)
      ->Args({kN})
      ->Name("zq/mul_shoup_vec_vt/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, ReduceU128)
      ->Args({kN})
      ->Name("zq/reduce_u128/4096")
      ->Iterations(50);
  BENCHMARK_REGISTER_F(ZqBenchmarkFixture, LazyMulShoup)
      ->Args({kN})
      ->Name("zq/lazy_mul_shoup/4096")
      ->Iterations(50);
}

// Call the registration function
static bool registered = []() {
  RegisterZqBenchmarks();
  return true;
}();

BENCHMARK_MAIN();
