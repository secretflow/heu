#ifndef SAMPLE_VEC_CBD_H
#define SAMPLE_VEC_CBD_H

#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

namespace bfv {
namespace math {
namespace utils {

/**
 * @brief Sample a vector of independent centered binomial distributions of a
 * given variance.
 *
 * @param vector_size The size of the output vector
 * @param variance The variance of the centered binomial distribution (must be
 * between 1 and 16)
 * @param rng Random number generator
 * @return Vector of i64 values sampled from centered binomial distribution
 * @throws std::invalid_argument if variance is not between 1 and 16
 */
template <typename RNG>
std::vector<int64_t> sample_vec_cbd(size_t vector_size, size_t variance,
                                    RNG &rng);

// Explicit declaration for std::mt19937_64
std::vector<int64_t> sample_vec_cbd(size_t vector_size, size_t variance,
                                    std::mt19937_64 &rng);

}  // namespace utils
}  // namespace math
}  // namespace bfv
#endif  // SAMPLE_VEC_CBD_H
