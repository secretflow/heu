#ifndef MODULUS_RUNTIME_H
#define MODULUS_RUNTIME_H

#include <cstdint>
#include <random>

#include "math/arch.h"

namespace bfv::math::zq::internal {

struct RuntimeCapabilityProfile {
  std::uniform_int_distribution<uint64_t> distribution;
  Arch arch;
  bool has_avx2 = false;
  bool has_avx512f = false;
  bool has_bmi2 = false;
  bool has_adx = false;
};

RuntimeCapabilityProfile BuildRuntimeCapabilityProfile(uint64_t modulus);

}  // namespace bfv::math::zq::internal

#endif
