#include "math/poly_storage.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <utility>

#include "math/context.h"

namespace bfv::math::rq {

Poly::Impl::Impl(
    ::bfv::util::ArenaHandle pool_ /*= ::bfv::util::ArenaHandle::Shared()*/)
    : representation(Representation::PowerBasis),
      has_lazy_coefficients(false),
      allow_variable_time_computations(false),
      pool(std::move(pool_)),
      coefficients(),
      coefficients_shoup() {}

Poly::Impl::~Impl() = default;

Poly::Impl::Impl(const Impl &other)
    : ctx(other.ctx),
      representation(other.representation),
      has_lazy_coefficients(other.has_lazy_coefficients),
      allow_variable_time_computations(other.allow_variable_time_computations),
      pool(other.pool),
      coefficients(),
      coefficients_shoup() {
  size_t size = other.ctx->degree() * other.ctx->q().size();
  if (other.coefficients) {
    coefficients = pool.allocate<uint64_t>(size);
    std::copy_n(other.coefficients.get(), size, coefficients.get());
  }
  if (other.coefficients_shoup) {
    coefficients_shoup = pool.allocate<uint64_t>(size);
    std::copy_n(other.coefficients_shoup.get(), size, coefficients_shoup.get());
  }
}

Poly::Impl &Poly::Impl::operator=(const Impl &other) {
  if (this != &other) {
    ctx = other.ctx;
    representation = other.representation;
    has_lazy_coefficients = other.has_lazy_coefficients;
    allow_variable_time_computations = other.allow_variable_time_computations;
    pool = other.pool;

    size_t size = ctx->degree() * ctx->q().size();
    if (other.coefficients) {
      coefficients = pool.allocate<uint64_t>(size);
      std::copy_n(other.coefficients.get(), size, coefficients.get());
    } else {
      coefficients.release();
    }

    if (other.coefficients_shoup) {
      coefficients_shoup = pool.allocate<uint64_t>(size);
      std::copy_n(other.coefficients_shoup.get(), size,
                  coefficients_shoup.get());
    } else {
      coefficients_shoup.release();
    }
  }
  return *this;
}

Poly::Impl::Impl(Impl &&other) noexcept = default;

Poly::Impl &Poly::Impl::operator=(Impl &&other) noexcept = default;

void Poly::Impl::clear_multiply_hints() {
  if (coefficients_shoup) {
    std::fill_n(coefficients_shoup.get(), ctx->degree() * ctx->q().size(), 0);
  } else {
    std::cerr << "clear_multiply_hints missing hint buffer" << std::endl;
  }
}

void Poly::Impl::rebuild_multiply_hints() {
  const size_t degree = ctx->degree();
  const size_t num_moduli = ctx->q().size();

  if (!coefficients_shoup) {
    coefficients_shoup = pool.allocate<uint64_t>(num_moduli * degree);
  }

  for (size_t i = 0; i < num_moduli; ++i) {
    const auto &qi = ctx->q()[i];
    const uint64_t *coeffs_ptr = coefficients.get() + i * degree;
    uint64_t *hint_ptr = coefficients_shoup.get() + i * degree;

    for (size_t j = 0; j < degree; ++j) {
      hint_ptr[j] = qi.Shoup(coeffs_ptr[j]);
    }
  }
}

void Poly::Impl::ntt_forward() {
  const size_t degree = ctx->degree();
  (void)degree;
  for (size_t i = 0; i < ctx->ops().size(); ++i) {
    ctx->ops()[i].ForwardInPlace(coefficients.get() + i * degree);
  }
}

void Poly::Impl::ntt_backward() {
  const size_t degree = ctx->degree();
  (void)degree;
  for (size_t i = 0; i < ctx->ops().size(); ++i) {
    ctx->ops()[i].BackwardInPlace(coefficients.get() + i * degree);
  }
}

}  // namespace bfv::math::rq
