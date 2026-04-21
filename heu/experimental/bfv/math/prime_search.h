#ifndef PRIME_SEARCH_H
#define PRIME_SEARCH_H

#include <cstdint>
#include <optional>

namespace bfv::math::zq::internal {

bool PassesDeterministicPrimeWitnesses(uint64_t n);
bool SupportsSingleLimbFastPath(uint64_t modulus);
std::optional<uint64_t> FindPrimeWithCongruenceTail(size_t num_bits,
                                                    uint64_t modulo,
                                                    uint64_t upper_bound);

}  // namespace bfv::math::zq::internal

#endif
