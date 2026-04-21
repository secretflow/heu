#include <stdexcept>

#include "math/aux_base_plan_internal.h"
#include "math/biguint.h"

namespace bfv {
namespace math {
namespace internal {

void PopulateCorrectionChannelPlan(
    AuxiliaryLiftBackend &plan,
    const std::shared_ptr<const rq::Context> &base_ctx) {
  auto &converters = plan.converters;
  auto &correction = plan.correction;
  const size_t base_q_size = converters.base_q_size;

  correction.correction_modulus_mod_q.resize(base_q_size);
  correction.correction_inv_punctured_prod_mod_q.resize(base_q_size);
  correction.correction_inv_punctured_prod_mod_q_shoup.resize(base_q_size);
  correction.punctured_prod_q_mod_correction.resize(base_q_size);

  const auto &q_moduli = base_ctx->rns()->moduli();
  const auto &q_moduli_u64 = base_ctx->rns()->moduli_u64();
  const uint64_t correction_mask = correction.correction_modulus - 1;
  for (size_t i = 0; i < base_q_size; ++i) {
    correction.correction_modulus_mod_q[i] =
        q_moduli[i].Reduce(correction.correction_modulus);
    uint64_t punctured_prod_mod_qi = 1;
    uint64_t punctured_prod_mod_correction = 1;
    for (size_t j = 0; j < base_q_size; ++j) {
      if (i == j) {
        continue;
      }
      punctured_prod_mod_qi = q_moduli[i].Mul(
          punctured_prod_mod_qi, q_moduli[i].Reduce(q_moduli_u64[j]));
      punctured_prod_mod_correction =
          (punctured_prod_mod_correction * q_moduli_u64[j]) & correction_mask;
    }

    auto inverse_punctured_prod = q_moduli[i].Inv(punctured_prod_mod_qi);
    if (!inverse_punctured_prod.has_value()) {
      throw std::runtime_error(
          "Aux-base lift failed to invert a punctured product modulo q");
    }
    correction.correction_inv_punctured_prod_mod_q[i] =
        inverse_punctured_prod.value();
    correction.correction_inv_punctured_prod_mod_q_shoup[i] =
        q_moduli[i].Shoup(inverse_punctured_prod.value());
    correction.punctured_prod_q_mod_correction[i] =
        punctured_prod_mod_correction;
  }

  rns::BigUint prod_q = base_ctx->modulus();
  auto correction_modulus = zq::Modulus::New(correction.correction_modulus);
  if (!correction_modulus.has_value()) {
    throw std::runtime_error(
        "Aux-base lift failed to initialize the correction modulus");
  }
  const uint64_t prod_q_mod_correction =
      (prod_q % rns::BigUint(correction.correction_modulus)).to_u64();
  auto inverse_prod_q_mod_correction =
      correction_modulus->Inv(prod_q_mod_correction);
  if (!inverse_prod_q_mod_correction.has_value()) {
    throw std::runtime_error(
        "Aux-base lift failed to invert prod(q) in the correction modulus");
  }
  correction.neg_inv_prod_q_mod_correction =
      correction_modulus->Neg(inverse_prod_q_mod_correction.value());

  correction.prod_q_mod_aux_basis.resize(converters.aux_size);
  correction.prod_q_mod_aux_basis_shoup.resize(converters.aux_size);
  correction.inv_correction_modulus_mod_aux.resize(converters.aux_size);
  correction.inv_correction_modulus_mod_aux_shoup.resize(converters.aux_size);

  const auto &auxiliary_ops = converters.aux_basis_ctx->moduli();
  for (size_t i = 0; i < converters.aux_size; ++i) {
    const auto &aux_mod = auxiliary_ops[i];
    const uint64_t prod_q_mod = (prod_q % rns::BigUint(aux_mod.P())).to_u64();
    correction.prod_q_mod_aux_basis[i] = prod_q_mod;
    correction.prod_q_mod_aux_basis_shoup[i] = aux_mod.Shoup(prod_q_mod);

    const uint64_t correction_mod_aux =
        aux_mod.Reduce(correction.correction_modulus);
    auto inverse_correction = aux_mod.Inv(correction_mod_aux);
    if (!inverse_correction.has_value()) {
      throw std::runtime_error(
          "Aux-base lift failed to invert the correction modulus inside the "
          "auxiliary basis");
    }
    correction.inv_correction_modulus_mod_aux[i] = inverse_correction.value();
    correction.inv_correction_modulus_mod_aux_shoup[i] =
        aux_mod.Shoup(inverse_correction.value());
  }
}

}  // namespace internal
}  // namespace math
}  // namespace bfv
