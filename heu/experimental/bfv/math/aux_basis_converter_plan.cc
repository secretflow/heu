#include <stdexcept>
#include <vector>

#include "math/aux_base_plan_internal.h"
#include "math/base_converter.h"

namespace bfv {
namespace math {
namespace internal {

void PopulateAuxiliaryConverters(
    AuxiliaryLiftBackend &plan,
    const std::shared_ptr<const rq::Context> &base_ctx,
    const std::shared_ptr<const rq::Context> &mul_ctx) {
  const size_t base_q_size = base_ctx->moduli().size();
  const auto &base_moduli = base_ctx->moduli();
  const auto &mul_moduli = mul_ctx->moduli();

  if (mul_moduli.size() <= base_q_size) {
    throw std::runtime_error(
        "Aux-base lift requires an extended residue basis");
  }
  for (size_t i = 0; i < base_q_size; ++i) {
    if (mul_moduli[i] != base_moduli[i]) {
      throw std::runtime_error(
          "Aux-base lift requires the extended basis to preserve base-q order");
    }
  }

  auto &converters = plan.converters;
  auto &correction = plan.correction;

  converters.base_q_size = base_q_size;
  converters.aux_size = mul_moduli.size() - base_q_size;
  if (converters.aux_size < 2) {
    throw std::runtime_error(
        "Aux-base lift requires at least two auxiliary residues");
  }

  std::vector<uint64_t> auxiliary_moduli(mul_moduli.begin() + base_q_size,
                                         mul_moduli.end());
  converters.aux_basis_ctx =
      rns::RnsContext::create(std::move(auxiliary_moduli));

  correction.correction_modulus = uint64_t{1} << 32;
  correction.correction_modulus_div_2 = correction.correction_modulus >> 1;

  converters.main_to_aux_converter = std::make_unique<rns::BaseConverter>(
      std::const_pointer_cast<rns::RnsContext>(base_ctx->rns()),
      std::const_pointer_cast<rns::RnsContext>(converters.aux_basis_ctx));

  auto correction_ctx = rns::RnsContext::create(
      std::vector<uint64_t>{correction.correction_modulus});
  converters.main_to_correction_converter =
      std::make_unique<rns::BaseConverter>(
          std::const_pointer_cast<rns::RnsContext>(base_ctx->rns()),
          std::const_pointer_cast<rns::RnsContext>(correction_ctx));

  std::vector<uint64_t> augmented_aux_moduli =
      converters.aux_basis_ctx->moduli_u64();
  augmented_aux_moduli.push_back(correction.correction_modulus);
  auto augmented_aux_ctx =
      rns::RnsContext::create(std::move(augmented_aux_moduli));
  converters.main_to_augmented_aux_converter =
      std::make_unique<rns::BaseConverter>(
          std::const_pointer_cast<rns::RnsContext>(base_ctx->rns()),
          std::const_pointer_cast<rns::RnsContext>(augmented_aux_ctx));
}

}  // namespace internal
}  // namespace math
}  // namespace bfv
