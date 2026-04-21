#include "math/primes.h"

#include "math/prime_search.h"

namespace bfv {
namespace math {
namespace zq {

bool is_prime(uint64_t n) {
  return internal::PassesDeterministicPrimeWitnesses(n);
}

bool supports_opt(uint64_t p) {
  return internal::SupportsSingleLimbFastPath(p);
}

std::optional<uint64_t> generate_prime(size_t num_bits, uint64_t modulo,
                                       uint64_t upper_bound) {
  return internal::FindPrimeWithCongruenceTail(num_bits, modulo, upper_bound);
}

}  // namespace zq
}  // namespace math
}  // namespace bfv
