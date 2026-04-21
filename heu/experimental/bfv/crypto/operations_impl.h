#pragma once

#include <algorithm>
#include <cstring>

#include "crypto/exceptions.h"
#include "crypto/operations.h"

namespace bfv::crypto::bfv {

namespace detail {

/**
 * @brief Optimized fused multiply-add operation: out[i] += x[i] * y[i]
 *
 * This function performs vectorized FMA operations for better performance.
 * It processes elements in chunks of 16 for better cache utilization.
 *
 * @param out Output accumulator array (128-bit integers)
 * @param x First input array (64-bit integers)
 * @param y Second input array (64-bit integers)
 * @param n Number of elements to process
 */
inline void fma_u128(__uint128_t *out, const uint64_t *x, const uint64_t *y,
                     size_t n) {
  // Process in chunks of 16 for better performance
  const size_t chunk_size = 16;
  const size_t full_chunks = n / chunk_size;

  // Process full chunks
  for (size_t chunk = 0; chunk < full_chunks; ++chunk) {
    const size_t base_idx = chunk * chunk_size;

    // Unroll the loop for better performance
    for (size_t i = 0; i < chunk_size; ++i) {
      const size_t idx = base_idx + i;
      out[idx] +=
          static_cast<__uint128_t>(x[idx]) * static_cast<__uint128_t>(y[idx]);
    }
  }

  // Process remaining elements
  const size_t remaining_start = full_chunks * chunk_size;
  for (size_t i = remaining_start; i < n; ++i) {
    out[i] += static_cast<__uint128_t>(x[i]) * static_cast<__uint128_t>(y[i]);
  }
}

}  // namespace detail

template <typename CtIterator, typename PtIterator>
Ciphertext dot_product_scalar(CtIterator ct_begin, CtIterator ct_end,
                              PtIterator pt_begin, PtIterator pt_end) {
  // Calculate iterator distances
  const size_t ct_count = std::distance(ct_begin, ct_end);
  const size_t pt_count = std::distance(pt_begin, pt_end);
  const size_t count = std::min(ct_count, pt_count);

  if (count == 0) {
    throw BfvException("At least one iterator is empty");
  }

  // Get first ciphertext for parameter validation
  const auto &ct_first = *ct_begin;
  const auto &params = ct_first.parameters();
  const auto &ctx = params->context();

  // Validate parameters and ciphertext sizes
  auto ct_it = ct_begin;
  auto pt_it = pt_begin;
  for (size_t i = 0; i < count; ++i, ++ct_it, ++pt_it) {
    if (ct_it->parameters() != ct_first.parameters()) {
      throw BfvException("Mismatched parameters in ciphertexts");
    }
    if (pt_it->parameters() != ct_first.parameters()) {
      throw BfvException(
          "Mismatched parameters between ciphertext and plaintext");
    }
    if (ct_it->size() != ct_first.size()) {
      throw BfvException("Mismatched number of parts in the ciphertexts");
    }
  }

  // Calculate maximum accumulation values for each modulus
  std::vector<__uint128_t> max_acc;
  max_acc.reserve(ctx->moduli().size());
  for (uint64_t qi : ctx->moduli()) {
    // Calculate how many bits are available for accumulation
    uint32_t leading_zeros = __builtin_clzll(qi);
    max_acc.push_back(1ULL << (2 * leading_zeros));
  }

  __uint128_t min_of_max = *std::min_element(max_acc.begin(), max_acc.end());

  if (static_cast<__uint128_t>(count) > min_of_max) {
    // Too many ciphertexts for optimized method, use polynomial dot product
    std::vector<::bfv::math::rq::Polynomial> result_polys;
    result_polys.reserve(ct_first.size());

    for (size_t i = 0; i < ct_first.size(); ++i) {
      std::vector<const ::bfv::math::rq::Polynomial *> ct_polys;
      std::vector<const ::bfv::math::rq::Polynomial *> pt_polys;

      ct_polys.reserve(count);
      pt_polys.reserve(count);

      ct_it = ct_begin;
      pt_it = pt_begin;
      for (size_t j = 0; j < count; ++j, ++ct_it, ++pt_it) {
        ct_polys.push_back(&ct_it->polynomial(i));
        pt_polys.push_back(&pt_it->polynomial_ntt());
      }

      // Use the polynomial dot product from math library
      auto result_poly = ::bfv::math::rq::dot_product(ct_polys, pt_polys);
      result_polys.push_back(std::move(result_poly));
    }

    return Ciphertext::from_polynomials_with_level(
        result_polys, ct_first.parameters(), ct_first.level());
  } else {
    // Use optimized accumulation method
    const size_t degree = ct_first.parameters()->degree();
    const size_t num_moduli = ctx->moduli().size();
    const size_t ct_size = ct_first.size();

    // Initialize accumulator: [ct_size][num_moduli][degree]
    std::vector<std::vector<std::vector<__uint128_t>>> acc(
        ct_size, std::vector<std::vector<__uint128_t>>(
                     num_moduli, std::vector<__uint128_t>(degree, 0)));

    // Accumulate products
    ct_it = ct_begin;
    pt_it = pt_begin;
    for (size_t iter = 0; iter < count; ++iter, ++ct_it, ++pt_it) {
      const auto &pt_poly = pt_it->polynomial_ntt();

      for (size_t i = 0; i < ct_size; ++i) {
        const auto &ct_poly = ct_it->polynomial(i);

        for (size_t j = 0; j < num_moduli; ++j) {
          detail::fma_u128(acc[i][j].data(), ct_poly.data(j), pt_poly.data(j),
                           degree);
        }
      }
    }

    // Reduce accumulated values
    std::vector<::bfv::math::rq::Polynomial> result_polys;
    result_polys.reserve(ct_size);

    for (size_t i = 0; i < ct_size; ++i) {
      std::vector<std::vector<uint64_t>> coeffs(num_moduli,
                                                std::vector<uint64_t>(degree));

      for (size_t j = 0; j < num_moduli; ++j) {
        const auto &modulus_op = ctx->modulus_operator(j);
        for (size_t k = 0; k < degree; ++k) {
          coeffs[j][k] = modulus_op.reduce_u128(acc[i][j][k]);
        }
      }

      auto poly = ::bfv::math::rq::Polynomial::from_coefficients(
          coeffs, ctx, ::bfv::math::rq::Representation::Ntt);
      result_polys.push_back(std::move(poly));
    }

    return Ciphertext::from_polynomials_with_level(
        result_polys, ct_first.parameters(), ct_first.level());
  }
}

}  // namespace bfv::crypto::bfv
