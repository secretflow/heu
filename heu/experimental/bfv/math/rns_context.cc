#include "math/rns_context.h"

#include <cassert>
#include <memory>
#include <stdexcept>
#include <vector>

#include "math/rns_context_layout.h"

namespace bfv {
namespace math {
namespace rns {

class RnsContext::Impl {
 public:
  using ResidueBasis = internal::ResidueBasisData;
  using ReconstructionCache = internal::ReconstructionCacheData;
  using AlignedBuffers = internal::AlignedBufferData;
  using AlignedPtr = internal::AlignedPtr;

  ResidueBasis basis;
  ReconstructionCache reconstruction;
  AlignedBuffers aligned;
  AlignedPtr aligned_basis_storage;
  AlignedPtr aligned_inverse_storage;

  explicit Impl(const std::vector<uint64_t> &mods) {
    internal::ValidateResidueBasis(mods);
    basis = internal::BuildResidueBasisData(mods);
    internal::AllocateAlignedResidueBuffers(basis.count, aligned_basis_storage,
                                            aligned_inverse_storage, aligned);
    reconstruction = internal::BuildReconstructionCacheData(basis, aligned);
  }
};

RnsContext::RnsContext(const std::vector<uint64_t> &moduli_u64)
    : impl_(std::make_unique<Impl>(moduli_u64)) {}

RnsContext::~RnsContext() = default;

std::shared_ptr<RnsContext> RnsContext::create(
    const std::vector<uint64_t> &moduli_u64) {
  return std::make_shared<RnsContext>(moduli_u64);
}

const BigUint &RnsContext::modulus() const {
  return impl_->reconstruction.basis_product;
}

// Project into residue channels while reusing aligned basis storage.
std::vector<uint64_t> RnsContext::project(const BigUint &a) const {
  std::vector<uint64_t> rests;
  rests.reserve(impl_->basis.count);

  // Use aligned basis values to keep residue extraction cache-friendly.
  for (size_t i = 0; i < impl_->basis.count; ++i) {
    rests.push_back((a % impl_->aligned.basis_values[i]).to_u64());
  }
  return rests;
}

// Reconstruct through cached lift terms and a single final reduction.
BigUint RnsContext::lift(const std::vector<uint64_t> &rests) const {
  if (rests.size() != impl_->basis.count) {
    throw std::runtime_error(
        "Residue-channel count does not match the active RNS basis");
  }

  BigUint result = BigUint::zero();

  for (size_t i = 0; i < impl_->basis.count; ++i) {
    BigUint term = impl_->reconstruction.lift_terms[i] * rests[i];
    result += term;
  }

  return result % impl_->reconstruction.basis_product;
}

BigUint RnsContext::get_garner(size_t i) const {
  if (i >= impl_->reconstruction.lift_terms.size()) {
    throw std::out_of_range("Requested reconstruction term is out of range");
  }
  return impl_->reconstruction.lift_terms[i];
}

const std::vector<uint64_t> &RnsContext::moduli_u64() const {
  return impl_->basis.basis_values_u64;
}

const std::vector<zq::Modulus> &RnsContext::moduli() const {
  return impl_->basis.residue_operators;
}

const std::vector<BigUint> &RnsContext::garner() const {
  return impl_->reconstruction.lift_terms;
}

}  // namespace rns
}  // namespace math
}  // namespace bfv
