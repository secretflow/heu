#include "math/ntt.h"

#include <gtest/gtest.h>

#include <random>
#include <vector>

#include "math/modulus.h"
#include "math/primes.h"

using namespace bfv::math::ntt;
using namespace bfv::math;

class NttTest : public ::testing::Test {};

namespace {

uint64_t BuildTransformEligiblePrime() {
  auto prime = zq::generate_prime(18, 2 * 1024, (uint64_t{1} << 18) - 1);
  if (!prime.has_value()) {
    throw std::runtime_error("Failed to generate supported NTT prime");
  }
  return *prime;
}

uint64_t BuildTransformIneligiblePrime() {
  for (uint64_t candidate = (uint64_t{1} << 11) - 1; candidate > 64;
       candidate -= 2) {
    if (zq::is_prime(candidate) && !SupportsNtt(candidate, 1024)) {
      return candidate;
    }
  }
  throw std::runtime_error("Failed to generate unsupported NTT prime");
}

const std::vector<uint64_t> &ConstructorPrimeSet() {
  static const std::vector<uint64_t> primes = {
      BuildTransformIneligiblePrime(),
      BuildTransformEligiblePrime(),
  };
  return primes;
}

}  // namespace

TEST_F(NttTest, Constructor) {
  std::vector<size_t> sizes = {32, 1024};
  const auto &ps = ConstructorPrimeSet();
  for (auto size : sizes) {
    for (auto p_val : ps) {
      auto q_opt = zq::Modulus::New(p_val);
      ASSERT_TRUE(q_opt.has_value());
      zq::Modulus q = q_opt.value();
      bool supports = SupportsNtt(p_val, size);
      auto op = NttOperator::New(q, size);
      if (supports) {
        ASSERT_TRUE(op.has_value());
      } else {
        ASSERT_FALSE(op.has_value());
      }
    }
  }
}

TEST_F(NttTest, Bijection) {
  const int ntests = 100;
  std::mt19937_64 rng(20260315);
  std::vector<size_t> sizes = {32, 1024};
  const auto &ps = ConstructorPrimeSet();
  for (auto size : sizes) {
    for (auto p_val : ps) {
      auto q_opt = zq::Modulus::New(p_val);
      ASSERT_TRUE(q_opt.has_value());
      zq::Modulus q = q_opt.value();
      if (SupportsNtt(p_val, size)) {
        auto op_opt = NttOperator::New(q, size);
        ASSERT_TRUE(op_opt.has_value());
        NttOperator op = op_opt.value();
        for (int i = 0; i < ntests; ++i) {
          std::vector<uint64_t> a = q.RandomVec(size, rng);
          std::vector<uint64_t> a_clone = a;
          std::vector<uint64_t> b = a;

          a = op.Forward(a);
          ASSERT_NE(a, a_clone);

          b = op.ForwardVt(b);
          ASSERT_EQ(a, b);
          a = op.Backward(a);

          ASSERT_EQ(a, a_clone);
          b = op.BackwardVt(b);
          ASSERT_EQ(a, b);
        }
      }
    }
  }
}

TEST_F(NttTest, ForwardLazy) {
  const int ntests = 100;
  std::mt19937_64 rng(20260316);
  std::vector<size_t> sizes = {32, 1024};
  const auto &ps = ConstructorPrimeSet();
  for (auto size : sizes) {
    for (auto p_val : ps) {
      auto q_opt = zq::Modulus::New(p_val);
      ASSERT_TRUE(q_opt.has_value());
      zq::Modulus q = q_opt.value();
      if (SupportsNtt(p_val, size)) {
        auto op_opt = NttOperator::New(q, size);
        ASSERT_TRUE(op_opt.has_value());
        NttOperator op = op_opt.value();
        for (int i = 0; i < ntests; ++i) {
          std::vector<uint64_t> a = q.RandomVec(size, rng);
          std::vector<uint64_t> a_lazy = a;
          a = op.Forward(a);
          a_lazy = op.ForwardVtLazy(a_lazy);
          q.ReduceVec(a_lazy);
          ASSERT_EQ(a, a_lazy);
        }
      }
    }
  }
}
