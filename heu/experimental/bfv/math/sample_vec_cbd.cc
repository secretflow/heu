#include "sample_vec_cbd.h"

#include <random>
#include <stdexcept>

namespace bfv {
namespace math {
namespace utils {

template <typename RNG>
std::vector<int64_t> sample_vec_cbd(size_t vector_size, size_t variance,
                                    RNG &rng) {
  if (variance < 1 || variance > 16) {
    throw std::invalid_argument("The variance should be between 1 and 16");
  }

  std::vector<int64_t> out;
  out.reserve(vector_size);

  const size_t number_bits = 4 * variance;

  const __uint128_t mask_add = static_cast<__uint128_t>(
      (UINT64_MAX >> (64 - number_bits)) >> (2 * variance));

  const __uint128_t mask_sub = mask_add << (2 * variance);

  __uint128_t current_pool = 0;

  size_t current_pool_nbits = 0;

  for (size_t i = 0; i < vector_size; ++i) {
    if (current_pool_nbits < number_bits) {
      current_pool |= static_cast<__uint128_t>(rng()) << current_pool_nbits;
      current_pool_nbits += 64;
    }

    __uint128_t add_bits = current_pool & mask_add;
    __uint128_t sub_bits = current_pool & mask_sub;

    // Count bits in 128-bit integers by splitting into two 64-bit parts
    int64_t add_count =
        __builtin_popcountll(static_cast<uint64_t>(add_bits)) +
        __builtin_popcountll(static_cast<uint64_t>(add_bits >> 64));
    int64_t sub_count =
        __builtin_popcountll(static_cast<uint64_t>(sub_bits)) +
        __builtin_popcountll(static_cast<uint64_t>(sub_bits >> 64));

    out.push_back(add_count - sub_count);

    current_pool >>= number_bits;

    current_pool_nbits -= number_bits;
  }

  return out;
}

// Explicit template instantiation for common RNG types
template std::vector<int64_t> sample_vec_cbd<std::mt19937_64>(
    size_t, size_t, std::mt19937_64 &);
template std::vector<int64_t> sample_vec_cbd<std::random_device>(
    size_t, size_t, std::random_device &);

// Non-template wrapper for std::mt19937_64
std::vector<int64_t> sample_vec_cbd(size_t vector_size, size_t variance,
                                    std::mt19937_64 &rng) {
  return sample_vec_cbd<std::mt19937_64>(vector_size, variance, rng);
}

}  // namespace utils
}  // namespace math
}  // namespace bfv
