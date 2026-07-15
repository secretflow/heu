#include "math/modulus_runtime.h"

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

namespace bfv::math::zq::internal {

RuntimeCapabilityProfile BuildRuntimeCapabilityProfile(uint64_t modulus) {
  RuntimeCapabilityProfile profile;
  profile.distribution =
      std::uniform_int_distribution<uint64_t>(0, modulus - 1);

#if defined(__GNUC__) || defined(__clang__)
#if defined(__AVX2__)
  profile.has_avx2 = __builtin_cpu_supports("avx2");
#endif
#if defined(__AVX512F__)
  profile.has_avx512f = __builtin_cpu_supports("avx512f");
#endif
#if defined(__BMI2__)
  profile.has_bmi2 = __builtin_cpu_supports("bmi2");
#endif
#if defined(__ADX__)
  profile.has_adx = __builtin_cpu_supports("adx");
#endif
#else
#if defined(__AVX2__)
  profile.has_avx2 = true;
#endif
#if defined(__AVX512F__)
  profile.has_avx512f = true;
#endif
#if defined(__BMI2__)
  profile.has_bmi2 = true;
#endif
#if defined(__ADX__)
  profile.has_adx = true;
#endif
#endif

  return profile;
}

}  // namespace bfv::math::zq::internal
