
void Poly::multiply_accumulate(const Poly &factor, const Poly &term) {
  if (*pimpl_->ctx != *factor.pimpl_->ctx ||
      *pimpl_->ctx != *term.pimpl_->ctx) {
    throw DefaultException("Context mismatch in multiply_accumulate");
  }

  // The accumulation target must stay in Ntt form.
  if (pimpl_->representation != Representation::Ntt) {
    throw DefaultException("multiply_accumulate requires an Ntt accumulator");
  }

  const size_t degree = pimpl_->ctx->degree();
  const size_t num_moduli = pimpl_->ctx->q().size();
  bool use_variable_time = pimpl_->allow_variable_time_computations;

  if (term.pimpl_->representation == Representation::NttShoup) {
    if (term.pimpl_->coefficients_shoup == nullptr) {
      throw DefaultException(
          "NttShoup representation requires cached multiply hints");
    }

    for (size_t i = 0; i < num_moduli; ++i) {
      const auto &qi = pimpl_->ctx->q()[i];
      uint64_t *result_coeffs = data(i);
      const uint64_t *factor_coeffs = factor.data(i);
      const uint64_t *term_coeffs = term.data(i);
      const uint64_t *term_hints = term.data_shoup(i);

      if (use_variable_time) {
        for (size_t j = 0; j < degree; ++j) {
          uint64_t product =
              qi.MulShoupVt(factor_coeffs[j], term_coeffs[j], term_hints[j]);
          result_coeffs[j] = qi.AddVt(result_coeffs[j], product);
        }
      } else {
        for (size_t j = 0; j < degree; ++j) {
          uint64_t product =
              qi.MulShoup(factor_coeffs[j], term_coeffs[j], term_hints[j]);
          result_coeffs[j] = qi.Add(result_coeffs[j], product);
        }
      }
    }
  } else if (term.pimpl_->representation == Representation::Ntt) {
    // Plain Ntt multiply-add path.
    for (size_t i = 0; i < num_moduli; ++i) {
      const auto &qi = pimpl_->ctx->q()[i];
      uint64_t *result_coeffs = data(i);
      const uint64_t *factor_coeffs = factor.data(i);
      const uint64_t *term_coeffs = term.data(i);

      if (use_variable_time) {
        for (size_t j = 0; j < degree; ++j) {
          uint64_t product = qi.MulVt(factor_coeffs[j], term_coeffs[j]);
          result_coeffs[j] = qi.AddVt(result_coeffs[j], product);
        }
      } else {
        for (size_t j = 0; j < degree; ++j) {
          uint64_t product = qi.Mul(factor_coeffs[j], term_coeffs[j]);
          result_coeffs[j] = qi.Add(result_coeffs[j], product);
        }
      }
    }
  } else {
    throw DefaultException(
        "multiply_accumulate received an unsupported representation");
  }
}
