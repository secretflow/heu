#include "math/base_change_plan.h"

#include <stdexcept>

namespace bfv::math::rns::internal {

namespace {

AlignedWordBuffer AllocateAlignedWords(size_t count) {
  void *ptr = nullptr;
  if (posix_memalign(&ptr, 32, count * sizeof(uint64_t)) != 0) {
    throw std::bad_alloc();
  }
  return AlignedWordBuffer(static_cast<uint64_t *>(ptr));
}

}  // namespace

BaseChangePlanData BuildBaseChangePlan(
    const std::shared_ptr<RnsContext> &ibase,
    const std::shared_ptr<RnsContext> &obase) {
  BaseChangePlanData plan;

  const size_t input_basis_count = ibase->moduli().size();
  const size_t output_basis_count = obase->moduli().size();
  const auto &input_moduli = ibase->moduli();
  const auto &output_moduli = obase->moduli();
  const auto &input_moduli_u64 = ibase->moduli_u64();

  plan.input_scale_storage = AllocateAlignedWords(input_basis_count);
  plan.input_scale_factors = plan.input_scale_storage.get();

  plan.input_scale_hint_storage = AllocateAlignedWords(input_basis_count);
  plan.input_scale_hints = plan.input_scale_hint_storage.get();

  for (size_t i = 0; i < input_basis_count; ++i) {
    uint64_t punctured_prod_mod_qi = 1;
    for (size_t j = 0; j < input_basis_count; ++j) {
      if (i != j) {
        uint64_t qj_mod_qi = input_moduli[i].Reduce(input_moduli_u64[j]);
        punctured_prod_mod_qi =
            input_moduli[i].Mul(punctured_prod_mod_qi, qj_mod_qi);
      }
    }

    auto inv_opt = input_moduli[i].Inv(punctured_prod_mod_qi);
    if (!inv_opt) {
      throw std::runtime_error(
          "Failed to compute modular inverse for base converter");
    }
    plan.input_scale_factors[i] = *inv_opt;
    plan.input_scale_hints[i] =
        input_moduli[i].Shoup(plan.input_scale_factors[i]);
  }

  size_t matrix_size = output_basis_count * input_basis_count;
  plan.output_mix_storage = AllocateAlignedWords(matrix_size);
  plan.output_mix_matrix = plan.output_mix_storage.get();

  plan.output_mix_hint_storage = AllocateAlignedWords(matrix_size);
  plan.output_mix_hints = plan.output_mix_hint_storage.get();

  for (size_t j = 0; j < output_basis_count; ++j) {
    for (size_t i = 0; i < input_basis_count; ++i) {
      uint64_t punctured_prod_mod_pj = 1;
      for (size_t k = 0; k < input_basis_count; ++k) {
        if (i != k) {
          uint64_t qk_mod_pj = output_moduli[j].Reduce(input_moduli_u64[k]);
          punctured_prod_mod_pj =
              output_moduli[j].Mul(punctured_prod_mod_pj, qk_mod_pj);
        }
      }

      size_t idx = j * input_basis_count + i;
      plan.output_mix_matrix[idx] = punctured_prod_mod_pj;
      plan.output_mix_hints[idx] =
          output_moduli[j].Shoup(plan.output_mix_matrix[idx]);
    }
  }

  return plan;
}

}  // namespace bfv::math::rns::internal
