#pragma once

#include <iterator>
#include <vector>

#include "crypto/ciphertext.h"
#include "crypto/plaintext.h"

namespace crypto {
namespace bfv {

/**
 * @brief Compute the dot product between an iterator of Ciphertext and an
 * iterator of Plaintext.
 *
 * This function computes the dot product between ciphertexts and plaintexts
 * efficiently, using optimized accumulation when possible
 *
 * @tparam CtIterator Iterator type for ciphertexts
 * @tparam PtIterator Iterator type for plaintexts
 * @param ct_begin Begin iterator for ciphertexts
 * @param ct_end End iterator for ciphertexts
 * @param pt_begin Begin iterator for plaintexts
 * @param pt_end End iterator for plaintexts
 * @return Ciphertext The result of the dot product
 * @throws ParameterException if iterators are empty, parameters don't match, or
 * ciphertexts have different sizes
 */
template <typename CtIterator, typename PtIterator>
Ciphertext dot_product_scalar(CtIterator ct_begin, CtIterator ct_end,
                              PtIterator pt_begin, PtIterator pt_end);

/**
 * @brief Convenience function for dot product with containers
 *
 * @tparam CtContainer Container type for ciphertexts
 * @tparam PtContainer Container type for plaintexts
 * @param ct_container Container of ciphertexts
 * @param pt_container Container of plaintexts
 * @return Ciphertext The result of the dot product
 */
template <typename CtContainer, typename PtContainer>
Ciphertext dot_product_scalar(const CtContainer &ct_container,
                              const PtContainer &pt_container) {
  return dot_product_scalar(ct_container.begin(), ct_container.end(),
                            pt_container.begin(), pt_container.end());
}

}  // namespace bfv
}  // namespace crypto

#include "crypto/dot_product_impl.h"
