#pragma once

#include "crypto/evaluation_key.h"
#include "crypto/rng_bridge.h"

namespace crypto {
namespace bfv {

// Template implementations for EvaluationKeyBuilder

template <typename RNG>
EvaluationKey EvaluationKeyBuilder::build(RNG &rng) {
  return detail::WithMt19937_64(
      rng, [&](std::mt19937_64 &std_rng) { return build(std_rng); });
}

}  // namespace bfv
}  // namespace crypto
