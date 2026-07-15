#ifndef CONTEXT_LAYOUT_H
#define CONTEXT_LAYOUT_H

#include <cstdint>
#include <memory>
#include <vector>

#include "math/context.h"
#include "math/ntt.h"
#include "math/rns_context.h"

namespace bfv::math::rq::internal {

struct RingLayoutData {
  std::vector<uint64_t> basis_moduli;
  std::vector<::bfv::math::zq::Modulus> residue_operators;
  std::shared_ptr<::bfv::math::rns::RnsContext> residue_basis;
  size_t polynomial_degree = 0;
};

struct TransformLayoutData {
  std::vector<::bfv::math::ntt::NttOperator> transform_operators;
  std::vector<size_t> slot_permutation;
};

struct LevelSwitchLayoutData {
  std::vector<uint64_t> tail_to_head_inverse;
  std::vector<uint64_t> tail_to_head_inverse_shoup;
};

std::vector<size_t> BuildSlotPermutationLayout(size_t degree);

RingLayoutData BuildRingLayout(const std::vector<uint64_t> &moduli,
                               size_t degree);

TransformLayoutData BuildTransformLayout(const RingLayoutData &ring);

LevelSwitchLayoutData BuildLevelSwitchLayout(const RingLayoutData &ring);

std::shared_ptr<Context> BuildLowerLevelChain(
    const std::vector<uint64_t> &moduli, size_t degree);

}  // namespace bfv::math::rq::internal

#endif
