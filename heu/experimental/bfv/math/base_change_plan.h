#ifndef BASE_CHANGE_PLAN_H
#define BASE_CHANGE_PLAN_H

#include <cstdint>
#include <cstdlib>
#include <memory>

#include "math/rns_context.h"

namespace bfv::math::rns::internal {

struct AlignedFree {
  void operator()(void *ptr) const { free(ptr); }
};

using AlignedWordBuffer = std::unique_ptr<uint64_t[], AlignedFree>;

struct BaseChangePlanData {
  AlignedWordBuffer input_scale_storage;
  AlignedWordBuffer input_scale_hint_storage;
  AlignedWordBuffer output_mix_storage;
  AlignedWordBuffer output_mix_hint_storage;
  uint64_t *input_scale_factors = nullptr;
  uint64_t *input_scale_hints = nullptr;
  uint64_t *output_mix_matrix = nullptr;
  uint64_t *output_mix_hints = nullptr;
};

BaseChangePlanData BuildBaseChangePlan(
    const std::shared_ptr<RnsContext> &ibase,
    const std::shared_ptr<RnsContext> &obase);

}  // namespace bfv::math::rns::internal

#endif
