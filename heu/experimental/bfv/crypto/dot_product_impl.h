#pragma once

#include <algorithm>

#include "crypto/dot_product.h"
#include "crypto/operators.h"
#include "math/context.h"
#include "math/poly.h"

namespace crypto {
namespace bfv {

template <typename CtIterator, typename PtIterator>
Ciphertext dot_product_scalar(CtIterator ct_begin, CtIterator ct_end,
                              PtIterator pt_begin, PtIterator pt_end) {
  // Calculate iterator distances
  const size_t ct_count = std::distance(ct_begin, ct_end);
  const size_t pt_count = std::distance(pt_begin, pt_end);
  const size_t count = std::min(ct_count, pt_count);

  if (count == 0) {
    throw ParameterException("At least one iterator is empty");
  }

  // Get first ciphertext for parameter validation
  const auto &ct_first = *ct_begin;

  // Validate parameters and ciphertext sizes
  auto ct_it = ct_begin;
  auto pt_it = pt_begin;
  for (size_t i = 0; i < count; ++i, ++ct_it, ++pt_it) {
    if (*ct_it->parameters() != *ct_first.parameters()) {
      throw ParameterException("Mismatched parameters in ciphertexts");
    }
    if (*pt_it->parameters() != *ct_first.parameters()) {
      throw ParameterException(
          "Mismatched parameters between ciphertext and plaintext");
    }
    if (ct_it->size() != ct_first.size()) {
      throw ParameterException("Mismatched number of parts in the ciphertexts");
    }
  }

  // Simplified implementation: compute sum of products manually
  auto result = Ciphertext::zero(ct_first.parameters());

  ct_it = ct_begin;
  pt_it = pt_begin;
  for (size_t i = 0; i < count; ++i, ++ct_it, ++pt_it) {
    result = result + (*ct_it * *pt_it);
  }

  return result;
}

}  // namespace bfv
}  // namespace crypto
