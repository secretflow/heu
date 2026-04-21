#include "math/modulus.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <random>
#include <vector>

#include "math/primes.h"

using namespace bfv::math::zq;

// Helper functions if needed, e.g., for proptest simulation

// Test fixture for Modulus tests
class ModulusTest : public ::testing::Test {
 protected:
  // Common setup
};

// Constructor test
TEST_F(ModulusTest, Constructor) {
  uint64_t p = 3;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  EXPECT_EQ(mod.P(), p);
  // For proptest, simulate with multiple values
  std::vector<uint64_t> primes = {3, 5, 7, 11};
  for (auto q : primes) {
    auto m_opt = Modulus::New(q);
    ASSERT_TRUE(m_opt);
    const Modulus &m = m_opt.value();
    EXPECT_EQ(m.P(), q);
    EXPECT_TRUE(m.SupportsOpt() == ::bfv::math::zq::supports_opt(q));
  }
}

// Neg test
TEST_F(ModulusTest, Neg) {
  // Simulate proptest with loops
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  for (uint64_t x = 0; x < p; ++x) {
    uint64_t neg_x = mod.Neg(x);
    EXPECT_EQ(mod.Add(neg_x, x), 0);
  }
}

// Add test
TEST_F(ModulusTest, Add) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  for (uint64_t x = 0; x < p; ++x) {
    for (uint64_t y = 0; y < p; ++y) {
      uint64_t sum = mod.Add(x, y);
      EXPECT_EQ(sum, (x + y) % p);
    }
  }
}

TEST_F(ModulusTest, Sub) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  for (uint64_t x = 0; x < p; ++x) {
    for (uint64_t y = 0; y < p; ++y) {
      uint64_t diff = mod.Sub(x, y);
      EXPECT_EQ(diff, (x + p - y) % p);
    }
  }
}

TEST_F(ModulusTest, Mul) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  for (uint64_t x = 0; x < p; ++x) {
    for (uint64_t y = 0; y < p; ++y) {
      uint64_t prod = mod.Mul(x, y);
      EXPECT_EQ(prod, (x * y) % p);
    }
  }
}

TEST_F(ModulusTest, MulShoup) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  for (uint64_t x = 0; x < p; ++x) {
    for (uint64_t y = 0; y < p; ++y) {
      uint64_t y_shoup = mod.Shoup(y);
      uint64_t prod = mod.MulShoup(x, y, y_shoup);
      EXPECT_EQ(prod, (x * y) % p);
    }
  }
}

TEST_F(ModulusTest, MulOptimizedAllowsLargeMultiplicand) {
  uint64_t p = 2305843009211596801ULL;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();

  std::vector<uint64_t> xs = {0,
                              1,
                              p - 1,
                              p,
                              p + 1,
                              (p << 1) - 1,
                              (p << 1) + 12345,
                              std::numeric_limits<uint64_t>::max() - 1024};
  std::vector<uint64_t> ys = {1, 3, 17, 65537, p - 2};

  for (uint64_t x : xs) {
    for (uint64_t y : ys) {
      auto y_prepared = mod.PrepareMultiplyOperand(y);
      __uint128_t expected_wide =
          (static_cast<__uint128_t>(x) % p) * static_cast<__uint128_t>(y);
      uint64_t expected = mod.ReduceU128(expected_wide);
      EXPECT_EQ(mod.MulOptimized(x, y_prepared), expected)
          << "x=" << x << " y=" << y;
    }
  }
}

TEST_F(ModulusTest, MulShoupAllowsLargeMultiplicand) {
  uint64_t p = 2305843009211596801ULL;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();

  std::vector<uint64_t> xs = {0,
                              1,
                              p - 1,
                              p,
                              p + 7,
                              (p << 1) - 3,
                              (p << 1) + 99,
                              std::numeric_limits<uint64_t>::max() - 2048};
  std::vector<uint64_t> ys = {1, 5, 19, 65539, p - 7};

  for (uint64_t x : xs) {
    for (uint64_t y : ys) {
      uint64_t y_shoup = mod.Shoup(y);
      __uint128_t expected_wide =
          (static_cast<__uint128_t>(x) % p) * static_cast<__uint128_t>(y);
      uint64_t expected = mod.ReduceU128(expected_wide);
      EXPECT_EQ(mod.MulShoup(x, y, y_shoup), expected)
          << "x=" << x << " y=" << y;
    }
  }
}

TEST_F(ModulusTest, Reduce) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  for (uint64_t x = 0; x < 100; ++x) {
    EXPECT_EQ(mod.Reduce(x), x % p);
  }
}

TEST_F(ModulusTest, ReduceU128) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  for (__int128 x = 0; x < 100; ++x) {
    __int128 mod_p = x % static_cast<__int128>(p);
    EXPECT_EQ(mod.ReduceU128(x), static_cast<uint64_t>(mod_p));
  }
}

TEST_F(ModulusTest, LazyReduce) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  for (uint64_t x = 0; x < 2 * p; ++x) {
    uint64_t reduced = mod.LazyReduce(x);
    EXPECT_GE(reduced, 0);
    EXPECT_LT(reduced, 2 * p);
    EXPECT_EQ(reduced % p, x % p);
  }
}

TEST_F(ModulusTest, AddVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a = {1, 2, 3};
  std::vector<uint64_t> b = {4, 5, 6};
  std::vector<uint64_t> result = a;
  mod.AddVec(result, b);
  EXPECT_EQ(result, std::vector<uint64_t>({5 % p, 7 % p, 9 % p}));
  // Add more comprehensive checks
}

TEST_F(ModulusTest, SubVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a = {1, 2, 3};
  std::vector<uint64_t> b = {4, 5, 6};
  std::vector<uint64_t> result = a;
  mod.SubVec(result, b);
  EXPECT_EQ(result, std::vector<uint64_t>(
                        {(1 + p - 4) % p, (2 + p - 5) % p, (3 + p - 6) % p}));
}

TEST_F(ModulusTest, MulVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a = {1, 2, 3};
  std::vector<uint64_t> b = {4, 5, 6};
  std::vector<uint64_t> result = a;
  mod.MulVec(result, b);
  EXPECT_EQ(result, std::vector<uint64_t>({4 % p, 10 % p, 18 % p}));
}

TEST_F(ModulusTest, ScalarMulVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a = {1, 2, 3};
  uint64_t scalar = 4;
  std::vector<uint64_t> result = a;
  mod.ScalarMulVec(result, scalar);
  EXPECT_EQ(result, std::vector<uint64_t>({4 % p, 8 % p, 12 % p}));
}

TEST_F(ModulusTest, MulShoupVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a = {1, 2, 3};
  std::vector<uint64_t> b = {4, 5, 6};
  std::vector<uint64_t> b_shoup = mod.ShoupVec(b);
  std::vector<uint64_t> result = a;
  mod.MulShoupVec(result, b, b_shoup);
  EXPECT_EQ(result, std::vector<uint64_t>({4 % p, 10 % p, 18 % p}));
}

TEST_F(ModulusTest, ReduceVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a = {18, 19, 20};
  std::vector<uint64_t> result = a;
  mod.ReduceVec(result);
  EXPECT_EQ(result, std::vector<uint64_t>({1, 2, 3}));
}

TEST_F(ModulusTest, LazyReduceVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a = {18, 19, 20};
  std::vector<uint64_t> result = a;
  mod.LazyReduceVec(result);
  for (size_t i = 0; i < a.size(); ++i) {
    EXPECT_GE(result[i], 0);
    EXPECT_LT(result[i], 2 * p);
    EXPECT_EQ(result[i] % p, a[i] % p);
  }
}

TEST_F(ModulusTest, NegVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a = {1, 2, 3};
  std::vector<uint64_t> result = a;
  mod.NegVec(result);
  for (size_t i = 0; i < a.size(); ++i) {
    EXPECT_EQ(mod.Add(result[i], a[i]), 0);
  }
}

TEST_F(ModulusTest, RandomVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::mt19937_64 rng(0x4D4F44554C555331ULL);
  std::vector<uint64_t> result = mod.RandomVec(10, rng);
  EXPECT_EQ(result.size(), 10);
  for (auto x : result) {
    EXPECT_LT(x, p);
  }
}

TEST_F(ModulusTest, SerializeVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a(8, 1);
  std::vector<uint8_t> serialized = mod.SerializeVec(a);
  EXPECT_EQ(serialized.size(), mod.SerializationLength(a.size()));
}

TEST_F(ModulusTest, DeserializeVec) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a(8, 1);
  std::vector<uint8_t> serialized = mod.SerializeVec(a);
  std::vector<uint64_t> deserialized = mod.DeserializeVec(serialized);
  EXPECT_EQ(deserialized, a);
}

TEST_F(ModulusTest, ReduceI64) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  for (int64_t x = -50; x < 50; ++x) {
    uint64_t reduced = mod.ReduceI64(x);
    uint64_t expected = (x < 0) ? (p - static_cast<uint64_t>(-x % p)) % p
                                : static_cast<uint64_t>(x % p);
    EXPECT_EQ(reduced, expected);
  }
}

TEST_F(ModulusTest, ReduceVecI64) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<int64_t> a = {-1, -2, 3};
  std::vector<uint64_t> result = mod.ReduceVecI64(a);
  EXPECT_EQ(result, std::vector<uint64_t>({16, 15, 3}));
}

TEST_F(ModulusTest, ReduceVecNew) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  std::vector<uint64_t> a = {18, 19, 20};
  std::vector<uint64_t> result = mod.ReduceVecNew(a);
  EXPECT_EQ(result, std::vector<uint64_t>({1, 2, 3}));
  // Assuming ReduceVecNew is an optimized or alternative reduce
}

// For serialization, implement or assume transcode functions
TEST_F(ModulusTest, Pow) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  EXPECT_EQ(mod.Pow(2, 3), 8 % p);
}

TEST_F(ModulusTest, Inv) {
  uint64_t p = 17;
  auto mod_opt = Modulus::New(p);
  ASSERT_TRUE(mod_opt);
  const Modulus &mod = mod_opt.value();
  for (uint64_t x = 1; x < p; ++x) {
    auto inv = mod.Inv(x);
    ASSERT_TRUE(inv.has_value());
    EXPECT_EQ(mod.Mul(*inv, x), 1);
  }
  EXPECT_FALSE(mod.Inv(0).has_value());
}
