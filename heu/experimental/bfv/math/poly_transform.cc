#include <algorithm>
#include <cstdint>

#include "math/basis_mapper.h"
#include "math/context_transfer.h"
#include "math/exceptions.h"
#include "math/poly_storage.h"

namespace bfv::math::rq {

void Poly::change_representation(Representation to) {
  switch (pimpl_->representation) {
    case Representation::PowerBasis:
      switch (to) {
        case Representation::Ntt:
          pimpl_->ntt_forward();
          break;
        case Representation::NttShoup:
          pimpl_->ntt_forward();
          pimpl_->rebuild_multiply_hints();
          break;
        case Representation::PowerBasis:
          break;
      }
      break;

    case Representation::Ntt:
      switch (to) {
        case Representation::PowerBasis:
          pimpl_->ntt_backward();
          break;
        case Representation::NttShoup:
          pimpl_->rebuild_multiply_hints();
          break;
        case Representation::Ntt:
          break;
      }
      break;

    case Representation::NttShoup:
      if (to != Representation::NttShoup) {
        pimpl_->clear_multiply_hints();
        pimpl_->coefficients_shoup = nullptr;
      }
      switch (to) {
        case Representation::PowerBasis:
          pimpl_->ntt_backward();
          break;
        case Representation::Ntt:
          break;
        case Representation::NttShoup:
          break;
      }
      break;
  }

  pimpl_->representation = to;
}

void Poly::override_representation(Representation to) {
  if (pimpl_->coefficients_shoup) {
    pimpl_->clear_multiply_hints();
    pimpl_->coefficients_shoup = nullptr;
  }
  if (to == Representation::NttShoup) {
    pimpl_->rebuild_multiply_hints();
  }
  pimpl_->representation = to;
}

Poly Poly::substitute(const SubstitutionExponent &i) const {
  auto result = uninitialized(pimpl_->ctx, pimpl_->representation);

  if (pimpl_->allow_variable_time_computations) {
    result.pimpl_->allow_variable_time_computations = true;
  }

  switch (pimpl_->representation) {
    case Representation::Ntt:
    case Representation::NttShoup: {
      const auto &table = i.power_bitrev();
      const size_t degree = pimpl_->ctx->degree();
      const size_t num_moduli = pimpl_->ctx->q().size();

      for (size_t mod_idx = 0; mod_idx < num_moduli; ++mod_idx) {
        const uint64_t *input = data(mod_idx);
        uint64_t *output = result.data(mod_idx);

        for (size_t j = 0; j < degree; ++j) {
          output[j] = input[table[j]];
        }
      }

      if (pimpl_->representation == Representation::NttShoup) {
        for (size_t mod_idx = 0; mod_idx < num_moduli; ++mod_idx) {
          const uint64_t *input_hints = data_shoup(mod_idx);
          uint64_t *output_hints = result.data_shoup(mod_idx);

          if (input_hints && output_hints) {
            for (size_t j = 0; j < degree; ++j) {
              output_hints[j] = input_hints[table[j]];
            }
          }
        }
      }
      break;
    }

    case Representation::PowerBasis: {
      const size_t degree = pimpl_->ctx->degree();
      const size_t mask = degree - 1;
      const size_t exponent = i.exponent();
      const size_t num_moduli = pimpl_->ctx->q().size();

      for (size_t mod_idx = 0; mod_idx < num_moduli; ++mod_idx) {
        const auto &qi = pimpl_->ctx->q()[mod_idx];
        const uint64_t modulus_value = qi.P();
        const uint64_t *input_ptr =
            pimpl_->coefficients.get() + mod_idx * degree;
        uint64_t *output_ptr =
            result.pimpl_->coefficients.get() + mod_idx * degree;
        size_t index_raw = 0;

        for (size_t j = 0; j < degree; ++j, index_raw += exponent) {
          const size_t target_idx = index_raw & mask;
          uint64_t result_value = input_ptr[j];
          if (index_raw & degree) {
            const int64_t non_zero = (result_value != 0);
            result_value = (modulus_value - result_value) &
                           static_cast<uint64_t>(-non_zero);
          }
          output_ptr[target_idx] = result_value;
        }
      }
      break;
    }
  }

  return result;
}

void Poly::drop_last_residue() {
  if (!pimpl_->ctx->next_context()) {
    throw DefaultException("Polynomial is already at the lowest ring level");
  }

  if (pimpl_->representation != Representation::PowerBasis) {
    throw DefaultException("drop_last_residue requires PowerBasis storage");
  }

  const auto &next_ctx = pimpl_->ctx->next_context();
  const size_t active_modulus_count = pimpl_->ctx->q().size();
  const auto &q_last = pimpl_->ctx->q().back();
  const uint64_t q_last_div_2 = q_last.P() / 2;
  const size_t degree = pimpl_->ctx->degree();

  uint64_t *last_coeffs_ptr =
      pimpl_->coefficients.get() + (active_modulus_count - 1) * degree;

  if (pimpl_->allow_variable_time_computations) {
    for (size_t j = 0; j < degree; ++j) {
      last_coeffs_ptr[j] = q_last.AddVt(last_coeffs_ptr[j], q_last_div_2);
    }

    for (size_t i = 0; i < active_modulus_count - 1; ++i) {
      const auto &qi = pimpl_->ctx->q()[i];
      const auto &inv = pimpl_->ctx->inv_last_qi_mod_qj()[i];
      const auto &inv_shoup = pimpl_->ctx->inv_last_qi_mod_qj_shoup()[i];
      const uint64_t q_last_div_2_mod_qi = qi.P() - qi.ReduceVt(q_last_div_2);

      uint64_t *coeffs_ptr = pimpl_->coefficients.get() + i * degree;

      for (size_t j = 0; j < degree; ++j) {
        uint64_t tmp = qi.LazyReduce(last_coeffs_ptr[j]) + q_last_div_2_mod_qi;
        coeffs_ptr[j] += 3 * qi.P() - tmp;
        coeffs_ptr[j] = qi.Reduce(coeffs_ptr[j]);
        coeffs_ptr[j] = qi.MulShoup(coeffs_ptr[j], inv, inv_shoup);
      }
    }
  } else {
    for (size_t j = 0; j < degree; ++j) {
      last_coeffs_ptr[j] = q_last.Add(last_coeffs_ptr[j], q_last_div_2);
    }

    for (size_t i = 0; i < active_modulus_count - 1; ++i) {
      const auto &qi = pimpl_->ctx->q()[i];
      const auto &inv = pimpl_->ctx->inv_last_qi_mod_qj()[i];
      const auto &inv_shoup = pimpl_->ctx->inv_last_qi_mod_qj_shoup()[i];
      const uint64_t q_last_div_2_mod_qi = qi.P() - qi.Reduce(q_last_div_2);

      uint64_t *coeffs_ptr = pimpl_->coefficients.get() + i * degree;

      for (size_t j = 0; j < degree; ++j) {
        uint64_t tmp = qi.LazyReduce(last_coeffs_ptr[j]) + q_last_div_2_mod_qi;
        coeffs_ptr[j] += 3 * qi.P() - tmp;
        coeffs_ptr[j] = qi.Reduce(coeffs_ptr[j]);
        coeffs_ptr[j] = qi.MulShoup(coeffs_ptr[j], inv, inv_shoup);
      }
    }
  }

  if (!pimpl_->allow_variable_time_computations) {
    std::fill_n(last_coeffs_ptr, degree, 0);
  }

  pimpl_->ctx = next_ctx;
}

void Poly::drop_to_context(std::shared_ptr<const Context> context) {
  size_t niterations = pimpl_->ctx->niterations_to(context);

  for (size_t i = 0; i < niterations; ++i) {
    drop_last_residue();
  }

  if (*pimpl_->ctx != *context) {
    throw DefaultException(
        "drop_to_context failed to reach the requested ring level");
  }
}

Poly Poly::remap_to_context(const ContextTransfer &transfer) const {
  return transfer.apply(*this);
}

Poly Poly::map_to(const BasisMapper &mapper) const { return mapper.map(*this); }

void Poly::multiply_inverse_power_of_x(size_t power) {
  if (pimpl_->representation != Representation::PowerBasis) {
    throw DefaultException(
        "multiply_inverse_power_of_x requires PowerBasis representation");
  }

  const size_t degree = pimpl_->ctx->degree();
  const size_t shift = ((degree << 1) - power) % (degree << 1);
  const size_t mask = degree - 1;

  size_t total_size = degree * pimpl_->ctx->q().size();
  auto original_coefficients = pimpl_->pool.allocate<uint64_t>(total_size);
  std::copy_n(pimpl_->coefficients.get(), total_size,
              original_coefficients.get());

  const size_t num_moduli = pimpl_->ctx->q().size();
  for (size_t mod_idx = 0; mod_idx < num_moduli; ++mod_idx) {
    const auto &qi = pimpl_->ctx->q()[mod_idx];
    const uint64_t *orig_coeffs =
        original_coefficients.get() + mod_idx * degree;
    uint64_t *coeffs = pimpl_->coefficients.get() + mod_idx * degree;

    for (size_t k = 0; k < degree; ++k) {
      const size_t index = shift + k;
      const size_t target_idx = index & mask;

      if ((index & degree) == 0) {
        coeffs[target_idx] = orig_coeffs[k];
      } else {
        coeffs[target_idx] = qi.Neg(orig_coeffs[k]);
      }
    }
  }
}

}  // namespace bfv::math::rq
