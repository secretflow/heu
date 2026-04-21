#ifndef RNS_CONTEXT_LAYOUT_H
#define RNS_CONTEXT_LAYOUT_H

#include <cstdint>
#include <memory>
#include <vector>

#include "math/biguint.h"
#include "math/modulus.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

struct ResidueBasisData {
  std::vector<uint64_t> basis_values_u64;
  std::vector<zq::Modulus> residue_operators;
  size_t count = 0;
};

struct ReconstructionCacheData {
  std::vector<uint64_t> reconstruction_inverses;
  std::vector<uint64_t> reconstruction_inverse_hints;
  std::vector<BigUint> basis_partials;
  std::vector<BigUint> lift_terms;
  BigUint basis_product;
};

struct AlignedBufferData {
  uint64_t *basis_values = nullptr;
  uint64_t *reconstruction_inverses = nullptr;
};

struct AlignedDeleter {
  void operator()(void *ptr) const { free(ptr); }
};

using AlignedPtr = std::unique_ptr<uint64_t[], AlignedDeleter>;

void ValidateResidueBasis(const std::vector<uint64_t> &basis_values_u64);

void AllocateAlignedResidueBuffers(size_t count, AlignedPtr &basis_storage,
                                   AlignedPtr &inverse_storage,
                                   AlignedBufferData &aligned);

ResidueBasisData BuildResidueBasisData(const std::vector<uint64_t> &moduli_u64);

ReconstructionCacheData BuildReconstructionCacheData(
    const ResidueBasisData &basis, const AlignedBufferData &aligned);

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv

#endif
