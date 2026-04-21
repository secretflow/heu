#pragma once

#include "crypto/evaluation_key.h"

namespace crypto {
namespace bfv {

// Template implementations for EvaluationKeyBuilder

template <typename RNG>
EvaluationKey EvaluationKeyBuilder::build(RNG &rng) {
  // Forward to the implementation method
  return build(static_cast<std::mt19937_64 &>(rng));
}

}  // namespace bfv
}  // namespace crypto
