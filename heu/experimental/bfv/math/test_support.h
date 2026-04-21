#ifndef BFV_MATH_TEST_SUPPORT_H
#define BFV_MATH_TEST_SUPPORT_H

#include <algorithm>
#include <cstdint>
#include <memory>
#include <random>
#include <stdexcept>
#include <vector>

#include "math/biguint.h"
#include "math/primes.h"
#include "math/rns_context.h"
#include "math/scaling_factor.h"

namespace bfv::math::test {

inline std::vector<uint64_t> GenerateResidueBasisFixture(
    size_t count, size_t degree, size_t highest_bits = 52) {
  if (count == 0) {
    return {};
  }
  if (highest_bits < 10 || highest_bits < count + 9) {
    throw std::runtime_error("Unsupported basis generation request");
  }

  std::vector<uint64_t> basis;
  basis.reserve(count);
  const uint64_t modulo = static_cast<uint64_t>(degree) * 2;

  for (size_t idx = 0; idx < count; ++idx) {
    const size_t bits = highest_bits - idx;
    uint64_t upper_bound = (uint64_t{1} << bits) - 1 - modulo * idx;
    auto prime = ::bfv::math::zq::generate_prime(bits, modulo, upper_bound);
    while (prime &&
           std::find(basis.begin(), basis.end(), *prime) != basis.end()) {
      if (upper_bound <= modulo + 1) {
        prime.reset();
        break;
      }
      upper_bound -= modulo;
      prime = ::bfv::math::zq::generate_prime(bits, modulo, upper_bound);
    }
    if (!prime) {
      throw std::runtime_error("Failed to generate residue-basis fixture");
    }
    basis.push_back(*prime);
  }

  return basis;
}

inline std::vector<uint64_t> GenerateTaggedResidueBasis(uint64_t tag,
                                                        size_t count,
                                                        size_t degree,
                                                        size_t highest_bits) {
  const size_t bit_shift = static_cast<size_t>(tag % 3);
  const size_t min_bits = std::max<size_t>(10, count + 9);
  const size_t adjusted_bits =
      highest_bits > bit_shift ? highest_bits - bit_shift : min_bits;
  return GenerateResidueBasisFixture(count, degree,
                                     std::max(adjusted_bits, min_bits));
}

inline std::vector<uint64_t> BuildSingleResidueFixture(size_t degree,
                                                       uint64_t tag) {
  return GenerateTaggedResidueBasis(tag, 1, degree, 18);
}

inline std::vector<uint64_t> BuildContextChainFixture(size_t count,
                                                      size_t degree) {
  return GenerateTaggedResidueBasis(0x637478636861ULL, count, degree, 52);
}

inline ::bfv::math::rns::ScalingFactor BuildDerivedTransferFactor(
    const ::bfv::math::rns::BigUint &denominator) {
  constexpr uint64_t kCandidates[] = {641, 673, 709, 733, 797};
  for (uint64_t candidate : kCandidates) {
    if ((denominator % ::bfv::math::rns::BigUint(candidate)) !=
        ::bfv::math::rns::BigUint(0)) {
      return ::bfv::math::rns::ScalingFactor(
          ::bfv::math::rns::BigUint(candidate), denominator);
    }
  }
  return ::bfv::math::rns::ScalingFactor(::bfv::math::rns::BigUint(641),
                                         denominator);
}

inline std::vector<::bfv::math::rns::BigUint> BuildRoundedTransferReference(
    const std::vector<::bfv::math::rns::BigUint> &source_coeffs,
    const ::bfv::math::rns::BigUint &source_modulus,
    const ::bfv::math::rns::BigUint &target_modulus) {
  std::vector<::bfv::math::rns::BigUint> expected;
  expected.reserve(source_coeffs.size());
  const ::bfv::math::rns::BigUint half_source_modulus = source_modulus >> 1;

  for (const auto &coeff : source_coeffs) {
    expected.push_back((coeff * target_modulus + half_source_modulus) /
                       source_modulus);
  }

  return expected;
}

inline std::vector<std::vector<uint64_t>> MakeRandomResidueRows(
    const std::shared_ptr<::bfv::math::rns::RnsContext> &ctx, size_t count,
    uint64_t seed) {
  std::mt19937_64 rng(seed);
  std::vector<std::vector<uint64_t>> rows(ctx->moduli_u64().size(),
                                          std::vector<uint64_t>(count));
  for (size_t mod_idx = 0; mod_idx < ctx->moduli_u64().size(); ++mod_idx) {
    const uint64_t qi = ctx->moduli_u64()[mod_idx];
    for (size_t coeff_idx = 0; coeff_idx < count; ++coeff_idx) {
      rows[mod_idx][coeff_idx] = rng() % qi;
    }
  }
  return rows;
}

}  // namespace bfv::math::test

#endif  // BFV_MATH_TEST_SUPPORT_H
