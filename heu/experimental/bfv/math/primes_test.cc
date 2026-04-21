#include "math/primes.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <limits>
#include <vector>

namespace bfv {
namespace math {
namespace zq {

TEST(PrimesTest, GenerateDescendingPrimeWindow) {
  std::vector<uint64_t> generated;
  constexpr size_t kPrimeCount = 17;
  constexpr uint64_t kResidueStride = 2 * 16384;
  uint64_t upper_bound = (uint64_t{1} << 61) - 1;
  while (generated.size() != kPrimeCount) {
    auto p = generate_prime(61, kResidueStride, upper_bound);
    ASSERT_TRUE(p.has_value());
    upper_bound = p.value();
    generated.push_back(upper_bound);
  }
  ASSERT_EQ(generated.size(), kPrimeCount);

  auto descending = generated;
  std::sort(descending.begin(), descending.end(), std::greater<uint64_t>());
  EXPECT_EQ(generated, descending);

  auto unique = generated;
  std::sort(unique.begin(), unique.end());
  unique.erase(std::unique(unique.begin(), unique.end()), unique.end());
  EXPECT_EQ(unique.size(), generated.size());

  for (uint64_t prime : generated) {
    EXPECT_TRUE(is_prime(prime));
    EXPECT_EQ(prime % kResidueStride, 1U);
    EXPECT_GE(prime, (uint64_t{1} << 60));
    EXPECT_LT(prime, (uint64_t{1} << 61));
  }
}

TEST(PrimesTest, UpperBound) {
#ifdef NDEBUG
  GTEST_SKIP() << "Debug assert only tested in debug mode";
#else
  EXPECT_DEATH(generate_prime(62, 2 * 1048576, (1ULL << 62) + 1),
               "upper_bound larger than number of bits");
#endif
}

TEST(PrimesTest, ModuloTooLarge) {
  auto result = generate_prime(10, 2048, 1ULL << 10);
  EXPECT_FALSE(result.has_value());
}

TEST(PrimesTest, NotFound) {
  // 1033 is the first 11-bit prime congruent to 1 (mod 16); below that,
  // the search should fail.
  auto result = generate_prime(11, 16, 1033);
  EXPECT_FALSE(result.has_value());
}

}  // namespace zq
}  // namespace math
}  // namespace bfv
