#ifndef PULSAR_ZQ_PRIMES_H
#define PULSAR_ZQ_PRIMES_H

#include <cstdint>
#include <optional>

namespace bfv {
namespace math {
namespace zq {

bool is_prime(uint64_t n);

// Returns whether the modulus supports optimized multiplication and
// reduction. These optimized operations are possible when the modulus
// verifies Equation (1) of
// https://hal.archives-ouvertes.fr/hal-01242273/document.
bool supports_opt(uint64_t p);

// Generate a prime with bit length `num_bits` such that p % modulo == 1 and
// p < upper_bound. Requires 10 <= num_bits <= 62 and
// upper_bound <= (1 << num_bits).
std::optional<uint64_t> generate_prime(size_t num_bits, uint64_t modulo,
                                       uint64_t upper_bound);

}  // namespace zq
}  // namespace math
}  // namespace bfv

#endif  // PULSAR_ZQ_PRIMES_H
