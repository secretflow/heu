#ifndef BFV_MATH_RNS_RESIDUE_TRANSFER_ENGINE_H
#define BFV_MATH_RNS_RESIDUE_TRANSFER_ENGINE_H

#include <memory>
#include <vector>

#include "math/rns_context.h"
#include "math/scaling_factor.h"
#include "util/arena_allocator.h"

namespace bfv {
namespace math {
namespace ntt {
class NttOperator;
}  // namespace ntt
}  // namespace math
}  // namespace bfv

namespace bfv {
namespace math {
namespace rns {

enum class RnsScalingScheme {
  ResidueTransfer = 0,
  AuxBase = 1,
};

using util::ArenaHandle;

class ResidueTransferEngine {
 private:
  class Impl;
  std::unique_ptr<Impl> impl_;

 public:
  ResidueTransferEngine(const std::shared_ptr<RnsContext> &from,
                        const std::shared_ptr<RnsContext> &to,
                        const ScalingFactor &scaling_factor);
  ~ResidueTransferEngine();

  std::shared_ptr<RnsContext> from() const;
  std::shared_ptr<RnsContext> to() const;

  std::vector<uint64_t> scale_new(const std::vector<uint64_t> &rests,
                                  size_t size) const;

  void scale(const std::vector<uint64_t> &rests, std::vector<uint64_t> &out,
             size_t starting_index,
             ArenaHandle pool = ArenaHandle::Shared()) const;

  void scale(const uint64_t *rests, uint64_t *out, size_t starting_index,
             ArenaHandle pool = ArenaHandle::Shared()) const;

  void scale_poly(const std::vector<std::vector<uint64_t>> &coeffs_matrix,
                  std::vector<std::vector<uint64_t>> &out_matrix,
                  size_t starting_index,
                  ArenaHandle pool = ArenaHandle::Shared()) const;

  void scale_batch(const std::vector<const uint64_t *> &input_moduli_ptrs,
                   const std::vector<uint64_t *> &output_moduli_ptrs,
                   size_t count, size_t starting_index,
                   ArenaHandle pool = ArenaHandle::Shared()) const;

  void scale_multi_poly(
      const std::vector<std::vector<std::vector<uint64_t>>> &polys_coeffs,
      std::vector<std::vector<std::vector<uint64_t>>> &out_polys_coeffs,
      size_t starting_index, ArenaHandle pool = ArenaHandle::Shared()) const;

  bool uses_aux_base_multiply_path() const;
};

}  // namespace rns
}  // namespace math
}  // namespace bfv

#endif
