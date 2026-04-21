#include "math/context_layout.h"

#include <string>
#include <utility>
#include <vector>

#include "math/exceptions.h"

namespace bfv::math::rq::internal {

std::vector<size_t> BuildSlotPermutationLayout(size_t degree) {
  std::vector<size_t> slot_permutation(degree);
  slot_permutation[0] = 0;
  for (size_t slot = 1; slot < degree; ++slot) {
    slot_permutation[slot] =
        (slot_permutation[slot >> 1] >> 1) | ((slot & 1) ? (degree >> 1) : 0);
  }
  return slot_permutation;
}

RingLayoutData BuildRingLayout(const std::vector<uint64_t> &moduli,
                               size_t degree) {
  RingLayoutData ring;
  ring.polynomial_degree = degree;
  ring.basis_moduli = moduli;
  ring.residue_basis = ::bfv::math::rns::RnsContext::create(moduli);
  ring.residue_operators.reserve(moduli.size());

  for (uint64_t modulus : moduli) {
    auto qi = ::bfv::math::zq::Modulus::New(modulus);
    if (!qi) {
      throw DefaultException("Unsupported residue basis value: " +
                             std::to_string(modulus));
    }
    ring.residue_operators.push_back(std::move(*qi));
  }

  return ring;
}

TransformLayoutData BuildTransformLayout(const RingLayoutData &ring) {
  TransformLayoutData transforms;
  transforms.transform_operators.reserve(ring.basis_moduli.size());
  for (uint64_t modulus : ring.basis_moduli) {
    auto qi = ::bfv::math::zq::Modulus::New(modulus);
    auto op = ::bfv::math::ntt::NttOperator::New(*qi, ring.polynomial_degree);
    if (!op) {
      throw DefaultException(
          "Unable to build a transform operator for residue value " +
          std::to_string(modulus) + " and degree " +
          std::to_string(ring.polynomial_degree));
    }
    transforms.transform_operators.push_back(std::move(*op));
  }
  transforms.slot_permutation =
      BuildSlotPermutationLayout(ring.polynomial_degree);
  return transforms;
}

LevelSwitchLayoutData BuildLevelSwitchLayout(const RingLayoutData &ring) {
  LevelSwitchLayoutData level_switch;
  if (ring.basis_moduli.size() <= 1) {
    return level_switch;
  }

  const uint64_t tail_modulus = ring.basis_moduli.back();
  const size_t head_count = ring.basis_moduli.size() - 1;
  level_switch.tail_to_head_inverse.reserve(head_count);
  level_switch.tail_to_head_inverse_shoup.reserve(head_count);

  for (size_t idx = 0; idx < head_count; ++idx) {
    const auto &qi = ring.residue_operators[idx];
    const uint64_t tail_mod_head = qi.Reduce(tail_modulus);
    auto inv_opt = qi.Inv(tail_mod_head);
    if (!inv_opt) {
      throw DefaultException(
          "Unable to derive the cached tail-drop inverse for this ring level");
    }
    const uint64_t inv = *inv_opt;
    level_switch.tail_to_head_inverse.push_back(inv);
    level_switch.tail_to_head_inverse_shoup.push_back(qi.Shoup(inv));
  }

  return level_switch;
}

std::shared_ptr<Context> BuildLowerLevelChain(
    const std::vector<uint64_t> &moduli, size_t degree) {
  if (moduli.size() < 2) {
    return nullptr;
  }
  std::vector<uint64_t> next_moduli(moduli.begin(), moduli.end() - 1);
  return Context::create(next_moduli, degree);
}

}  // namespace bfv::math::rq::internal
