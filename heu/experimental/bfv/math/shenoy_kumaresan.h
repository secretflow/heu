#ifndef BFV_MATH_SHENOY_KUMARESAN_H
#define BFV_MATH_SHENOY_KUMARESAN_H

#include <cstdint>
#include <vector>

#include "math/modulus.h"

namespace bfv {
namespace math {

class ShenoyKumaresanCorrection {
 public:
  static void Apply(const std::vector<zq::Modulus> &target_moduli,
                    const std::vector<uint64_t> &prod_aux_body_mod_q,
                    const std::vector<uint64_t> &prod_aux_body_mod_q_shoup,
                    const std::vector<uint64_t> &neg_prod_aux_body_mod_q,
                    const std::vector<uint64_t> &neg_prod_aux_body_mod_q_shoup,
                    const uint64_t *alpha, uint64_t correction_modulus,
                    uint64_t correction_modulus_div_2,
                    uint64_t *const *output_moduli_ptrs, size_t count);
};

}  // namespace math
}  // namespace bfv

#endif  // BFV_MATH_SHENOY_KUMARESAN_H
