#include "math/shenoy_kumaresan.h"

namespace bfv {
namespace math {

void ShenoyKumaresanCorrection::Apply(
    const std::vector<zq::Modulus> &target_moduli,
    const std::vector<uint64_t> &prod_aux_body_mod_q,
    const std::vector<uint64_t> &prod_aux_body_mod_q_shoup,
    const std::vector<uint64_t> &neg_prod_aux_body_mod_q,
    const std::vector<uint64_t> &neg_prod_aux_body_mod_q_shoup,
    const uint64_t *alpha, uint64_t correction_modulus,
    uint64_t correction_modulus_div_2, uint64_t *const *output_moduli_ptrs,
    size_t count) {
  const size_t base_q_size = target_moduli.size();

  for (size_t i = 0; i < base_q_size; ++i) {
    const auto &qi = target_moduli[i];
    uint64_t prod = prod_aux_body_mod_q[i];
    uint64_t prod_shoup = prod_aux_body_mod_q_shoup[i];
    uint64_t neg_prod = neg_prod_aux_body_mod_q[i];
    uint64_t neg_prod_shoup = neg_prod_aux_body_mod_q_shoup[i];
    uint64_t *out = output_moduli_ptrs[i];

    for (size_t k = 0; k < count; ++k) {
      uint64_t a = alpha[k];
      if (a > correction_modulus_div_2) {
        uint64_t a_neg = correction_modulus - a;
        uint64_t a_red = qi.Reduce(a_neg);
        out[k] = qi.Add(out[k], qi.MulShoup(a_red, prod, prod_shoup));
      } else {
        uint64_t a_red = qi.Reduce(a);
        out[k] = qi.Add(out[k], qi.MulShoup(a_red, neg_prod, neg_prod_shoup));
      }
    }
  }
}

}  // namespace math
}  // namespace bfv
