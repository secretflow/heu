#include "math/rns_context_layout.h"

#include <algorithm>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

namespace bfv {
namespace math {
namespace rns {
namespace internal {

void ValidateResidueBasis(const std::vector<uint64_t> &basis_values_u64) {
  if (basis_values_u64.empty()) {
    throw std::runtime_error("RNS basis requires at least one residue value");
  }

  auto sorted_basis = basis_values_u64;
  std::sort(sorted_basis.begin(), sorted_basis.end());
  for (size_t i = 0; i < sorted_basis.size(); ++i) {
    for (size_t j = i + 1; j < sorted_basis.size(); ++j) {
      auto [d, _, __] = BigUint::extended_gcd(BigUint(sorted_basis[i]),
                                              BigUint(sorted_basis[j]));
      if (d != BigUint::one()) {
        throw std::runtime_error(
            "RNS basis values must remain pairwise coprime");
      }
    }
  }
}

void AllocateAlignedResidueBuffers(size_t count, AlignedPtr &basis_storage,
                                   AlignedPtr &inverse_storage,
                                   AlignedBufferData &aligned) {
  void *ptr = nullptr;
  if (posix_memalign(&ptr, 32, count * sizeof(uint64_t)) != 0) {
    throw std::bad_alloc();
  }
  basis_storage.reset(static_cast<uint64_t *>(ptr));
  aligned.basis_values = basis_storage.get();

  if (posix_memalign(&ptr, 32, count * sizeof(uint64_t)) != 0) {
    throw std::bad_alloc();
  }
  inverse_storage.reset(static_cast<uint64_t *>(ptr));
  aligned.reconstruction_inverses = inverse_storage.get();
}

ResidueBasisData BuildResidueBasisData(
    const std::vector<uint64_t> &moduli_u64) {
  ResidueBasisData basis;
  basis.basis_values_u64 = moduli_u64;
  basis.count = moduli_u64.size();
  basis.residue_operators.reserve(basis.count);

  for (uint64_t modulus_value : basis.basis_values_u64) {
    auto mod_opt = zq::Modulus::New(modulus_value);
    if (!mod_opt) {
      throw std::runtime_error(
          "Unable to build a residue operator for the requested basis value");
    }
    basis.residue_operators.emplace_back(std::move(*mod_opt));
  }

  return basis;
}

ReconstructionCacheData BuildReconstructionCacheData(
    const ResidueBasisData &basis, const AlignedBufferData &aligned) {
  ReconstructionCacheData reconstruction;
  reconstruction.reconstruction_inverses.reserve(basis.count);
  reconstruction.reconstruction_inverse_hints.reserve(basis.count);
  reconstruction.basis_partials.reserve(basis.count);
  reconstruction.lift_terms.reserve(basis.count);

  reconstruction.basis_product = BigUint::one();
  for (const auto &mod : basis.basis_values_u64) {
    reconstruction.basis_product *= mod;
  }

  for (size_t i = 0; i < basis.count; ++i) {
    uint64_t modulus_value = basis.basis_values_u64[i];
    BigUint basis_partial = reconstruction.basis_product / modulus_value;

    auto inverse_opt = basis_partial.mod_inverse(BigUint(modulus_value));
    if (!inverse_opt) {
      throw std::runtime_error(
          "Unable to derive a reconstruction inverse for the residue basis");
    }
    uint64_t reconstruction_inverse = inverse_opt->to_u64();
    BigUint lift_term = basis_partial * reconstruction_inverse;

    reconstruction.reconstruction_inverses.push_back(reconstruction_inverse);
    reconstruction.reconstruction_inverse_hints.push_back(
        basis.residue_operators[i].Shoup(reconstruction_inverse));
    reconstruction.basis_partials.push_back(std::move(basis_partial));
    reconstruction.lift_terms.push_back(std::move(lift_term));

    aligned.basis_values[i] = modulus_value;
    aligned.reconstruction_inverses[i] = reconstruction_inverse;
  }

  return reconstruction;
}

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv
