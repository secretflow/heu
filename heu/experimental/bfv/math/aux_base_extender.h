#ifndef BFV_MATH_AUX_BASE_EXTENDER_H
#define BFV_MATH_AUX_BASE_EXTENDER_H

#include <memory>
#include <optional>
#include <vector>

#include "math/base_converter.h"
#include "math/context.h"
#include "math/poly.h"
#include "math/rns_context.h"
#include "util/arena_allocator.h"

namespace bfv {
namespace math {

struct AuxiliaryLiftBackend {
  struct ConverterPlan {
    std::unique_ptr<rns::BaseConverter> main_to_aux_converter;
    std::unique_ptr<rns::BaseConverter> main_to_correction_converter;
    std::unique_ptr<rns::BaseConverter> main_to_augmented_aux_converter;
    std::shared_ptr<const rns::RnsContext> aux_basis_ctx;
    size_t base_q_size = 0;
    size_t aux_size = 0;
  };

  struct CorrectionPlan {
    uint64_t correction_modulus = 0;
    uint64_t correction_modulus_div_2 = 0;
    uint64_t neg_inv_prod_q_mod_correction = 0;
    std::vector<uint64_t> correction_modulus_mod_q;
    std::vector<uint64_t> correction_inv_punctured_prod_mod_q;
    std::vector<uint64_t> correction_inv_punctured_prod_mod_q_shoup;
    std::vector<uint64_t> punctured_prod_q_mod_correction;
    std::vector<uint64_t> prod_q_mod_aux_basis;
    std::vector<uint64_t> prod_q_mod_aux_basis_shoup;
    std::vector<uint64_t> inv_correction_modulus_mod_aux;
    std::vector<uint64_t> inv_correction_modulus_mod_aux_shoup;
  };

  ConverterPlan converters;
  CorrectionPlan correction;
};

class AuxBaseExtender {
 public:
  static void ExtendToNtt(const std::vector<const rq::Poly *> &polys,
                          const std::shared_ptr<const rq::Context> &base_ctx,
                          const std::shared_ptr<const rq::Context> &mul_ctx,
                          const AuxiliaryLiftBackend &params,
                          std::vector<rq::Poly> &out,
                          util::ArenaHandle pool = util::ArenaHandle::Shared());
};

}  // namespace math
}  // namespace bfv

#endif  // BFV_MATH_AUX_BASE_EXTENDER_H
