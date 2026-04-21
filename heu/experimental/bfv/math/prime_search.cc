#include "math/prime_search.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>

namespace bfv::math::zq::internal {

bool PassesDeterministicPrimeWitnesses(uint64_t n) {
  if (n < 2) {
    return false;
  }
  if (2 == n) {
    return true;
  }
  if (0 == (n & 0x1)) {
    return false;
  }
  if (3 == n) {
    return true;
  }
  if (0 == (n % 3)) {
    return false;
  }
  if (5 == n) {
    return true;
  }
  if (0 == (n % 5)) {
    return false;
  }
  if (7 == n) {
    return true;
  }
  if (0 == (n % 7)) {
    return false;
  }
  if (11 == n) {
    return true;
  }
  if (0 == (n % 11)) {
    return false;
  }
  if (13 == n) {
    return true;
  }
  if (0 == (n % 13)) {
    return false;
  }

  uint64_t d = n - 1;
  uint64_t r = 0;
  while (0 == (d & 0x1)) {
    d >>= 1;
    r++;
  }
  if (r == 0) {
    return false;
  }

  const uint64_t witnesses[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
  const size_t num_witnesses = sizeof(witnesses) / sizeof(witnesses[0]);

  for (size_t i = 0; i < num_witnesses; i++) {
    uint64_t a = witnesses[i];
    if (a >= n) {
      continue;
    }

    __uint128_t x = 1;
    __uint128_t base = a;
    __uint128_t exp = d;
    while (exp > 0) {
      if (exp & 1) {
        x = (x * base) % n;
      }
      base = (base * base) % n;
      exp >>= 1;
    }

    if (x == 1 || x == n - 1) {
      continue;
    }

    uint64_t count = 0;
    do {
      x = (x * x) % n;
      count++;
    } while (x != n - 1 && count < r - 1);

    if (x != n - 1) {
      return false;
    }
  }

  return true;
}

bool SupportsSingleLimbFastPath(uint64_t modulus) {
  if (__builtin_clzll(modulus) < 1) {
    return false;
  }

  uint32_t leading_zeros = __builtin_clzll(modulus);

  __uint128_t left_factor = (__uint128_t(1) << (3 * leading_zeros)) + 1;
  __uint128_t left_side = left_factor << 64;

  __uint128_t right_factor =
      (__uint128_t(1) << (3 * leading_zeros)) * ((1ULL << leading_zeros) + 1);
  __uint128_t right_side = right_factor * modulus;

  return left_side < right_side;
}

std::optional<uint64_t> FindPrimeWithCongruenceTail(size_t num_bits,
                                                    uint64_t modulo,
                                                    uint64_t upper_bound) {
  if (num_bits < 10 || num_bits > 62) {
    return std::nullopt;
  }

  if (upper_bound > (1ULL << num_bits)) {
    fprintf(stderr, "upper_bound larger than number of bits\n");
    std::abort();
  }

  uint32_t leading_zeros = 64 - num_bits;
  uint64_t candidate = upper_bound - 1;

  while (__builtin_clzll(candidate) != leading_zeros && candidate >= modulo) {
    candidate--;
  }

  while (candidate % modulo != 1 &&
         __builtin_clzll(candidate) == leading_zeros && candidate >= modulo) {
    candidate--;
  }

  while (__builtin_clzll(candidate) == leading_zeros && candidate >= modulo) {
    if (PassesDeterministicPrimeWitnesses(candidate)) {
      return candidate;
    }

    if (candidate < modulo) {
      break;
    }
    candidate -= modulo;
  }

  return std::nullopt;
}

}  // namespace bfv::math::zq::internal
