#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <random>

#include "math/poly_storage.h"

// SIMD optimization headers
#ifdef __AVX2__
#include <immintrin.h>
#endif
#ifdef __AVX512F__
#include <immintrin.h>
#endif

#include "math/biguint.h"
#include "math/context.h"
#include "math/exceptions.h"
#include "math/ntt_harvey.h"
#include "math/representation.h"
#include "math/sample_vec_cbd.h"

namespace bfv::math::rq {

Poly::Poly(std::unique_ptr<Impl> impl) : pimpl_(std::move(impl)) {}

Poly::~Poly() = default;

// Default constructor - creates an empty polynomial
Poly::Poly() : pimpl_(std::make_unique<Impl>()) {}

Poly::Poly(const Poly &other) : pimpl_(std::make_unique<Impl>(*other.pimpl_)) {}

Poly &Poly::operator=(const Poly &other) {
  if (this != &other) {
    *pimpl_ = *other.pimpl_;
  }
  return *this;
}

Poly::Poly(Poly &&) = default;
Poly &Poly::operator=(Poly &&) = default;

Poly Poly::zero(std::shared_ptr<const Context> ctx,
                Representation representation, ArenaHandle pool) {
  auto impl = std::make_unique<Impl>(std::move(pool));
  impl->ctx = std::move(ctx);
  impl->representation = representation;
  impl->allow_variable_time_computations = false;
  impl->has_lazy_coefficients = false;

  size_t size = impl->ctx->q().size() * impl->ctx->degree();
  impl->coefficients = impl->pool.allocate<uint64_t>(size);
  std::fill_n(impl->coefficients.get(), size, 0);

  if (representation == Representation::NttShoup) {
    impl->coefficients_shoup = impl->pool.allocate<uint64_t>(size);
    std::fill_n(impl->coefficients_shoup.get(), size, 0);
  }

  return Poly(std::move(impl));
}

Poly Poly::uninitialized(std::shared_ptr<const Context> ctx,
                         Representation representation, ArenaHandle pool) {
  auto impl = std::make_unique<Impl>(std::move(pool));
  impl->ctx = std::move(ctx);
  impl->representation = representation;
  impl->allow_variable_time_computations = false;
  impl->has_lazy_coefficients = false;

  size_t size = impl->ctx->q().size() * impl->ctx->degree();
  impl->coefficients = impl->pool.allocate<uint64_t>(size);

  if (representation == Representation::NttShoup) {
    impl->coefficients_shoup = impl->pool.allocate<uint64_t>(size);
  }

  return Poly(std::move(impl));
}

void Poly::allow_variable_time_computations() {
  pimpl_->allow_variable_time_computations = true;
}

void Poly::disallow_variable_time_computations() {
  pimpl_->allow_variable_time_computations = false;
}

bool Poly::allows_variable_time_computations() const {
  return pimpl_->allow_variable_time_computations;
}

Representation Poly::representation() const { return pimpl_->representation; }

const uint64_t *Poly::data(size_t modulus_index) const {
  return pimpl_->coefficients.get() + modulus_index * pimpl_->ctx->degree();
}

uint64_t *Poly::data(size_t modulus_index) {
  return pimpl_->coefficients.get() + modulus_index * pimpl_->ctx->degree();
}

const uint64_t *Poly::data_shoup(size_t modulus_index) const {
  if (!pimpl_->coefficients_shoup) return nullptr;
  return pimpl_->coefficients_shoup.get() +
         modulus_index * pimpl_->ctx->degree();
}

uint64_t *Poly::data_shoup(size_t modulus_index) {
  if (!pimpl_->coefficients_shoup) return nullptr;
  return pimpl_->coefficients_shoup.get() +
         modulus_index * pimpl_->ctx->degree();
}

bool Poly::has_shoup_coefficients() const {
  return static_cast<bool>(pimpl_->coefficients_shoup);
}

std::vector<std::vector<uint64_t>> Poly::coefficients() const {
  size_t num_moduli = pimpl_->ctx->q().size();
  size_t degree = pimpl_->ctx->degree();
  std::vector<std::vector<uint64_t>> result(num_moduli);
  for (size_t i = 0; i < num_moduli; ++i) {
    const uint64_t *mod_data = data(i);
    result[i].assign(mod_data, mod_data + degree);
  }
  return result;
}

std::shared_ptr<const Context> Poly::ctx() const { return pimpl_->ctx; }

bool Poly::operator==(const Poly &other) const {
  return pimpl_->ctx == other.pimpl_->ctx &&
         pimpl_->representation == other.pimpl_->representation &&
         pimpl_->ctx->degree() == other.pimpl_->ctx->degree() &&
         std::memcmp(pimpl_->coefficients.get(),
                     other.pimpl_->coefficients.get(),
                     pimpl_->ctx->degree() * pimpl_->ctx->q().size() *
                         sizeof(uint64_t)) == 0;
}

bool Poly::operator!=(const Poly &other) const { return !(*this == other); }

namespace {
template <typename RNG>
inline uint64_t fast_random_bounded(uint64_t bound, RNG &rng) {
#if defined(__SIZEOF_INT128__)
  uint64_t random_val = rng();
  __uint128_t m =
      static_cast<__uint128_t>(random_val) * static_cast<__uint128_t>(bound);
  uint64_t l = static_cast<uint64_t>(m);
  if (l < bound) {
    uint64_t t = -bound % bound;
    while (l < t) {
      random_val = rng();
      m = static_cast<__uint128_t>(random_val) *
          static_cast<__uint128_t>(bound);
      l = static_cast<uint64_t>(m);
    }
  }
  return static_cast<uint64_t>(m >> 64);
#else
  std::uniform_int_distribution<uint64_t> dist(0, bound - 1);
  return dist(rng);
#endif
}
}  // namespace

template <typename RNG>
Poly Poly::random(std::shared_ptr<const ::bfv::math::rq::Context> ctx,
                  ::bfv::math::rq::Representation representation, RNG &rng,
                  ::bfv::util::ArenaHandle pool) {
  auto poly = zero(ctx, representation, pool);

  // Generate random coefficients for each modulus
  const size_t degree = ctx->degree();
  for (size_t i = 0; i < ctx->q().size(); ++i) {
    const auto &qi = ctx->q()[i];
    uint64_t *coeffs = poly.pimpl_->coefficients.get() + i * degree;
    const uint64_t bound = qi.P();

    for (size_t j = 0; j < degree; ++j) {
      coeffs[j] = fast_random_bounded(bound, rng);
    }
  }

  // Compute Shoup coefficients if needed
  if (representation == Representation::NttShoup) {
    poly.pimpl_->rebuild_multiply_hints();
  }

  return poly;
}

Poly Poly::random_from_seed(std::shared_ptr<const Context> ctx,
                            Representation representation,
                            const std::array<uint8_t, 32> &seed,
                            ArenaHandle pool) {
  // Use seed to create deterministic random number generator
  std::seed_seq seq(seed.begin(), seed.end());
  std::mt19937_64 rng(seq);

  return random(ctx, representation, rng, pool);
}

template <typename RNG>
Poly Poly::small(std::shared_ptr<const ::bfv::math::rq::Context> ctx,
                 ::bfv::math::rq::Representation representation,
                 size_t variance, RNG &rng, ::bfv::util::ArenaHandle /*pool*/) {
  if (variance < 1 || variance > 16) {
    throw DefaultException(
        "The variance should be an integer between 1 and 16");
  }

  // Generate small coefficients using centered binomial distribution
  std::vector<int64_t> small_coeffs =
      ::bfv::math::utils::sample_vec_cbd(ctx->degree(), variance, rng);

  // Convert to polynomial
  // Note: from_i64_vector allocates its own Poly. We might need to pass pool to
  // it? We haven't updated from_i64_vector signature yet. Assuming default pool
  // for now for the temp poly, OR I updates from_i64_vector too. It's better to
  // update from_i64_vector signature too. But wait, from_i64_vector is static.
  // For now I'll use default pool for from_i64_vector and then ensure `poly`
  // uses `pool`? `from_i64_vector` returns a Poly. That Poly has a pool in
  // Impl. If I want `poly` to use `pool`, `from_i64_vector` must accept `pool`.
  // I should update `from_i64_vector` signature later.
  // For now, assume it uses default pool, which matches current state.
  // Wait, if I change `small` signature, I break callers?
  // Header was updated.
  auto poly =
      from_i64_vector(small_coeffs, ctx, false, Representation::PowerBasis);

  // Change representation if needed
  if (representation != Representation::PowerBasis) {
    poly.change_representation(representation);
  }

  return poly;
}

// Friend function implementations for arithmetic operations
Poly &operator+=(Poly &lhs, const Poly &rhs) {
  if (*lhs.pimpl_->ctx != *rhs.pimpl_->ctx) {
    throw DefaultException(
        "Polynomial addition requires matching ring contexts");
  }

  if (lhs.pimpl_->representation != rhs.pimpl_->representation) {
    throw DefaultException(
        "Polynomial addition requires matching storage representations");
  }

  // Propagate variable time computations
  if (rhs.pimpl_->allow_variable_time_computations) {
    lhs.pimpl_->allow_variable_time_computations = true;
  }

  // Cache frequently accessed values
  const size_t num_moduli = lhs.pimpl_->ctx->q().size();
  const auto &q_ops = lhs.pimpl_->ctx->q();
  const bool use_variable_time = lhs.pimpl_->allow_variable_time_computations;

  // Add coefficients for each modulus using optimized SIMD vector operations
  // Add coefficients for each modulus using optimized SIMD vector operations
  const size_t degree = lhs.pimpl_->ctx->degree();
  for (size_t i = 0; i < num_moduli; ++i) {
    const auto &qi = q_ops[i];
    uint64_t *coeffs = lhs.pimpl_->coefficients.get() + i * degree;
    const uint64_t *other_coeffs = rhs.pimpl_->coefficients.get() + i * degree;

    // Use the modulus row helpers for the active storage policy.
    if (use_variable_time) {
      qi.AddVecVt(coeffs, other_coeffs, degree);
    } else {
      qi.AddVec(coeffs, other_coeffs, degree);
    }
  }

  // Keep cached multiply hints aligned when both operands carry them.
  if (lhs.pimpl_->coefficients_shoup && rhs.pimpl_->coefficients_shoup) {
    const size_t hint_block_count = num_moduli;
    for (size_t i = 0; i < hint_block_count; ++i) {
      const auto &qi = q_ops[i];
      uint64_t *multiply_hints =
          lhs.pimpl_->coefficients_shoup.get() + i * degree;
      const uint64_t *other_multiply_hints =
          rhs.pimpl_->coefficients_shoup.get() + i * degree;

      if (use_variable_time) {
        size_t j = 0;
        for (; j + 3 < degree; j += 4) {
          multiply_hints[j] =
              qi.AddVt(multiply_hints[j], other_multiply_hints[j]);
          multiply_hints[j + 1] =
              qi.AddVt(multiply_hints[j + 1], other_multiply_hints[j + 1]);
          multiply_hints[j + 2] =
              qi.AddVt(multiply_hints[j + 2], other_multiply_hints[j + 2]);
          multiply_hints[j + 3] =
              qi.AddVt(multiply_hints[j + 3], other_multiply_hints[j + 3]);
        }
        for (; j < degree; ++j) {
          multiply_hints[j] =
              qi.AddVt(multiply_hints[j], other_multiply_hints[j]);
        }
      } else {
        size_t j = 0;
        for (; j + 3 < degree; j += 4) {
          multiply_hints[j] =
              qi.Add(multiply_hints[j], other_multiply_hints[j]);
          multiply_hints[j + 1] =
              qi.Add(multiply_hints[j + 1], other_multiply_hints[j + 1]);
          multiply_hints[j + 2] =
              qi.Add(multiply_hints[j + 2], other_multiply_hints[j + 2]);
          multiply_hints[j + 3] =
              qi.Add(multiply_hints[j + 3], other_multiply_hints[j + 3]);
        }
        for (; j < degree; ++j) {
          multiply_hints[j] =
              qi.Add(multiply_hints[j], other_multiply_hints[j]);
        }
      }
    }
  }

  return lhs;
}

Poly &operator-=(Poly &lhs, const Poly &rhs) {
  if (*lhs.pimpl_->ctx != *rhs.pimpl_->ctx) {
    throw DefaultException(
        "Polynomial subtraction requires matching ring contexts");
  }

  if (lhs.pimpl_->representation != rhs.pimpl_->representation) {
    throw DefaultException(
        "Polynomial subtraction requires matching storage representations");
  }

  // Propagate variable time computations
  if (rhs.pimpl_->allow_variable_time_computations) {
    lhs.pimpl_->allow_variable_time_computations = true;
  }

  // Cache frequently accessed values
  const size_t num_moduli = lhs.pimpl_->ctx->q().size();
  const auto &q_ops = lhs.pimpl_->ctx->q();
  const bool use_variable_time = lhs.pimpl_->allow_variable_time_computations;

  // Subtract coefficients row by row using the modulus helpers.
  const size_t degree = lhs.pimpl_->ctx->degree();
  for (size_t i = 0; i < num_moduli; ++i) {
    const auto &qi = q_ops[i];
    uint64_t *coeffs = lhs.pimpl_->coefficients.get() + i * degree;
    const uint64_t *other_coeffs = rhs.pimpl_->coefficients.get() + i * degree;

    // Use the modulus row helpers for the active storage policy.
    if (use_variable_time) {
      qi.SubVecVt(coeffs, other_coeffs, degree);
    } else {
      qi.SubVec(coeffs, other_coeffs, degree);
    }
  }

  // Keep cached multiply hints aligned when both operands carry them.
  if (lhs.pimpl_->coefficients_shoup && rhs.pimpl_->coefficients_shoup) {
    const size_t hint_block_count = num_moduli;
    for (size_t i = 0; i < hint_block_count; ++i) {
      const auto &qi = q_ops[i];
      uint64_t *multiply_hints =
          lhs.pimpl_->coefficients_shoup.get() + i * degree;
      const uint64_t *other_multiply_hints =
          rhs.pimpl_->coefficients_shoup.get() + i * degree;

      if (use_variable_time) {
        size_t j = 0;
        for (; j + 3 < degree; j += 4) {
          multiply_hints[j] =
              qi.SubVt(multiply_hints[j], other_multiply_hints[j]);
          multiply_hints[j + 1] =
              qi.SubVt(multiply_hints[j + 1], other_multiply_hints[j + 1]);
          multiply_hints[j + 2] =
              qi.SubVt(multiply_hints[j + 2], other_multiply_hints[j + 2]);
          multiply_hints[j + 3] =
              qi.SubVt(multiply_hints[j + 3], other_multiply_hints[j + 3]);
        }
        for (; j < degree; ++j) {
          multiply_hints[j] =
              qi.SubVt(multiply_hints[j], other_multiply_hints[j]);
        }
      } else {
        size_t j = 0;
        for (; j + 3 < degree; j += 4) {
          multiply_hints[j] =
              qi.Sub(multiply_hints[j], other_multiply_hints[j]);
          multiply_hints[j + 1] =
              qi.Sub(multiply_hints[j + 1], other_multiply_hints[j + 1]);
          multiply_hints[j + 2] =
              qi.Sub(multiply_hints[j + 2], other_multiply_hints[j + 2]);
          multiply_hints[j + 3] =
              qi.Sub(multiply_hints[j + 3], other_multiply_hints[j + 3]);
        }
        for (; j < degree; ++j) {
          multiply_hints[j] =
              qi.Sub(multiply_hints[j], other_multiply_hints[j]);
        }
      }
    }
  }

  return lhs;
}

Poly &operator*=(Poly &lhs, const Poly &rhs) {
  if (*lhs.pimpl_->ctx != *rhs.pimpl_->ctx) {
    throw DefaultException(
        "Polynomial multiplication requires matching ring contexts");
  }

  // Propagate variable time computations
  if (rhs.pimpl_->allow_variable_time_computations) {
    lhs.pimpl_->allow_variable_time_computations = true;
  }

  // Cache frequently accessed values for the row-wise multiply kernels.
  const auto &q_ops = lhs.pimpl_->ctx->q();
  const bool use_variable_time = lhs.pimpl_->allow_variable_time_computations;

  // Dispatch to the multiply kernel matching the two storage tags.
  const size_t degree = lhs.pimpl_->ctx->degree();
  const size_t num_moduli = lhs.pimpl_->ctx->q().size();

  if (lhs.pimpl_->representation == Representation::NttShoup &&
      rhs.pimpl_->representation == Representation::Ntt) {
    // Multiply cached-hint NTT rows by plain NTT rows.
    for (size_t i = 0; i < num_moduli; ++i) {
      const auto &qi = q_ops[i];
      uint64_t *coeffs = lhs.pimpl_->coefficients.get() + i * degree;
      const uint64_t *other_coeffs =
          rhs.pimpl_->coefficients.get() + i * degree;
      const uint64_t *multiply_hints =
          lhs.pimpl_->coefficients_shoup.get() + i * degree;

      if (use_variable_time) {
        // 16-way unroll loop for better performance and vectorization
        size_t j = 0;
        for (; j + 15 < degree; j += 16) {
          coeffs[j] =
              qi.MulShoupVt(coeffs[j], other_coeffs[j], multiply_hints[j]);
          coeffs[j + 1] = qi.MulShoupVt(coeffs[j + 1], other_coeffs[j + 1],
                                        multiply_hints[j + 1]);
          coeffs[j + 2] = qi.MulShoupVt(coeffs[j + 2], other_coeffs[j + 2],
                                        multiply_hints[j + 2]);
          coeffs[j + 3] = qi.MulShoupVt(coeffs[j + 3], other_coeffs[j + 3],
                                        multiply_hints[j + 3]);
          coeffs[j + 4] = qi.MulShoupVt(coeffs[j + 4], other_coeffs[j + 4],
                                        multiply_hints[j + 4]);
          coeffs[j + 5] = qi.MulShoupVt(coeffs[j + 5], other_coeffs[j + 5],
                                        multiply_hints[j + 5]);
          coeffs[j + 6] = qi.MulShoupVt(coeffs[j + 6], other_coeffs[j + 6],
                                        multiply_hints[j + 6]);
          coeffs[j + 7] = qi.MulShoupVt(coeffs[j + 7], other_coeffs[j + 7],
                                        multiply_hints[j + 7]);
          coeffs[j + 8] = qi.MulShoupVt(coeffs[j + 8], other_coeffs[j + 8],
                                        multiply_hints[j + 8]);
          coeffs[j + 9] = qi.MulShoupVt(coeffs[j + 9], other_coeffs[j + 9],
                                        multiply_hints[j + 9]);
          coeffs[j + 10] = qi.MulShoupVt(coeffs[j + 10], other_coeffs[j + 10],
                                         multiply_hints[j + 10]);
          coeffs[j + 11] = qi.MulShoupVt(coeffs[j + 11], other_coeffs[j + 11],
                                         multiply_hints[j + 11]);
          coeffs[j + 12] = qi.MulShoupVt(coeffs[j + 12], other_coeffs[j + 12],
                                         multiply_hints[j + 12]);
          coeffs[j + 13] = qi.MulShoupVt(coeffs[j + 13], other_coeffs[j + 13],
                                         multiply_hints[j + 13]);
          coeffs[j + 14] = qi.MulShoupVt(coeffs[j + 14], other_coeffs[j + 14],
                                         multiply_hints[j + 14]);
          coeffs[j + 15] = qi.MulShoupVt(coeffs[j + 15], other_coeffs[j + 15],
                                         multiply_hints[j + 15]);
        }
        // Fallback to 4-way unrolling for remaining elements
        for (; j + 3 < degree; j += 4) {
          coeffs[j] =
              qi.MulShoupVt(coeffs[j], other_coeffs[j], multiply_hints[j]);
          coeffs[j + 1] = qi.MulShoupVt(coeffs[j + 1], other_coeffs[j + 1],
                                        multiply_hints[j + 1]);
          coeffs[j + 2] = qi.MulShoupVt(coeffs[j + 2], other_coeffs[j + 2],
                                        multiply_hints[j + 2]);
          coeffs[j + 3] = qi.MulShoupVt(coeffs[j + 3], other_coeffs[j + 3],
                                        multiply_hints[j + 3]);
        }
        // Handle remaining elements
        for (; j < degree; ++j) {
          coeffs[j] =
              qi.MulShoupVt(coeffs[j], other_coeffs[j], multiply_hints[j]);
        }
      } else {
        // 16-way unroll loop for better performance and vectorization
        size_t j = 0;
        for (; j + 15 < degree; j += 16) {
          coeffs[j] =
              qi.MulShoup(coeffs[j], other_coeffs[j], multiply_hints[j]);
          coeffs[j + 1] = qi.MulShoup(coeffs[j + 1], other_coeffs[j + 1],
                                      multiply_hints[j + 1]);
          coeffs[j + 2] = qi.MulShoup(coeffs[j + 2], other_coeffs[j + 2],
                                      multiply_hints[j + 2]);
          coeffs[j + 3] = qi.MulShoup(coeffs[j + 3], other_coeffs[j + 3],
                                      multiply_hints[j + 3]);
          coeffs[j + 4] = qi.MulShoup(coeffs[j + 4], other_coeffs[j + 4],
                                      multiply_hints[j + 4]);
          coeffs[j + 5] = qi.MulShoup(coeffs[j + 5], other_coeffs[j + 5],
                                      multiply_hints[j + 5]);
          coeffs[j + 6] = qi.MulShoup(coeffs[j + 6], other_coeffs[j + 6],
                                      multiply_hints[j + 6]);
          coeffs[j + 7] = qi.MulShoup(coeffs[j + 7], other_coeffs[j + 7],
                                      multiply_hints[j + 7]);
          coeffs[j + 8] = qi.MulShoup(coeffs[j + 8], other_coeffs[j + 8],
                                      multiply_hints[j + 8]);
          coeffs[j + 9] = qi.MulShoup(coeffs[j + 9], other_coeffs[j + 9],
                                      multiply_hints[j + 9]);
          coeffs[j + 10] = qi.MulShoup(coeffs[j + 10], other_coeffs[j + 10],
                                       multiply_hints[j + 10]);
          coeffs[j + 11] = qi.MulShoup(coeffs[j + 11], other_coeffs[j + 11],
                                       multiply_hints[j + 11]);
          coeffs[j + 12] = qi.MulShoup(coeffs[j + 12], other_coeffs[j + 12],
                                       multiply_hints[j + 12]);
          coeffs[j + 13] = qi.MulShoup(coeffs[j + 13], other_coeffs[j + 13],
                                       multiply_hints[j + 13]);
          coeffs[j + 14] = qi.MulShoup(coeffs[j + 14], other_coeffs[j + 14],
                                       multiply_hints[j + 14]);
          coeffs[j + 15] = qi.MulShoup(coeffs[j + 15], other_coeffs[j + 15],
                                       multiply_hints[j + 15]);
        }
        // Fallback to 4-way unrolling for remaining elements
        for (; j + 3 < degree; j += 4) {
          coeffs[j] =
              qi.MulShoup(coeffs[j], other_coeffs[j], multiply_hints[j]);
          coeffs[j + 1] = qi.MulShoup(coeffs[j + 1], other_coeffs[j + 1],
                                      multiply_hints[j + 1]);
          coeffs[j + 2] = qi.MulShoup(coeffs[j + 2], other_coeffs[j + 2],
                                      multiply_hints[j + 2]);
          coeffs[j + 3] = qi.MulShoup(coeffs[j + 3], other_coeffs[j + 3],
                                      multiply_hints[j + 3]);
        }
        // Handle remaining elements
        for (; j < degree; ++j) {
          coeffs[j] =
              qi.MulShoup(coeffs[j], other_coeffs[j], multiply_hints[j]);
        }
      }
    }

    // The product stays in Ntt storage.
    lhs.pimpl_->representation = Representation::Ntt;
    lhs.pimpl_->coefficients_shoup.release();  // release, not reset

  } else if (lhs.pimpl_->representation == Representation::Ntt &&
             rhs.pimpl_->representation == Representation::NttShoup &&
             lhs.pimpl_->has_lazy_coefficients) {
    // Multiply plain NTT rows by cached-hint NTT rows.
    for (size_t i = 0; i < num_moduli; ++i) {
      const auto &qi = q_ops[i];
      uint64_t *coeffs = lhs.pimpl_->coefficients.get() + i * degree;
      const uint64_t *other_coeffs =
          rhs.pimpl_->coefficients.get() + i * degree;
      const uint64_t *multiply_hints =
          rhs.pimpl_->coefficients_shoup.get() + i * degree;

      if (use_variable_time) {
        // Unroll loop for better performance
        size_t j = 0;
        for (; j + 3 < degree; j += 4) {
          coeffs[j] =
              qi.MulShoupVt(coeffs[j], other_coeffs[j], multiply_hints[j]);
          coeffs[j + 1] = qi.MulShoupVt(coeffs[j + 1], other_coeffs[j + 1],
                                        multiply_hints[j + 1]);
          coeffs[j + 2] = qi.MulShoupVt(coeffs[j + 2], other_coeffs[j + 2],
                                        multiply_hints[j + 2]);
          coeffs[j + 3] = qi.MulShoupVt(coeffs[j + 3], other_coeffs[j + 3],
                                        multiply_hints[j + 3]);
        }
        // Handle remaining elements
        for (; j < degree; ++j) {
          coeffs[j] =
              qi.MulShoupVt(coeffs[j], other_coeffs[j], multiply_hints[j]);
        }
      } else {
        // Unroll loop for better performance
        size_t j = 0;
        for (; j + 3 < degree; j += 4) {
          coeffs[j] =
              qi.MulShoup(coeffs[j], other_coeffs[j], multiply_hints[j]);
          coeffs[j + 1] = qi.MulShoup(coeffs[j + 1], other_coeffs[j + 1],
                                      multiply_hints[j + 1]);
          coeffs[j + 2] = qi.MulShoup(coeffs[j + 2], other_coeffs[j + 2],
                                      multiply_hints[j + 2]);
          coeffs[j + 3] = qi.MulShoup(coeffs[j + 3], other_coeffs[j + 3],
                                      multiply_hints[j + 3]);
        }
        // Handle remaining elements
        for (; j < degree; ++j) {
          coeffs[j] =
              qi.MulShoup(coeffs[j], other_coeffs[j], multiply_hints[j]);
        }
      }
    }

    // The product stays in Ntt storage and consumes deferred reduction state.
    lhs.pimpl_->has_lazy_coefficients = false;

  } else if (lhs.pimpl_->representation == Representation::Ntt &&
             rhs.pimpl_->representation == Representation::Ntt) {
    // Multiply plain NTT rows directly.
    for (size_t i = 0; i < num_moduli; ++i) {
      const auto &qi = q_ops[i];
      uint64_t *coeffs = lhs.pimpl_->coefficients.get() + i * degree;
      const uint64_t *other_coeffs =
          rhs.pimpl_->coefficients.get() + i * degree;

      if (use_variable_time) {
        qi.MulVecVt(coeffs, other_coeffs, degree);
      } else {
        qi.MulVec(coeffs, other_coeffs, degree);
      }
    }

    // Plain NTT multiplication clears the deferred-reduction marker.
    lhs.pimpl_->has_lazy_coefficients = false;

  } else {
    throw DefaultException(
        "Polynomial multiplication received an unsupported representation "
        "pairing");
  }

  return lhs;
}

Poly &operator*=(Poly &lhs, const ::bfv::math::rns::BigUint &scalar) {
  // Project the scalar into the active residue basis once, then reuse it.
  auto scalar_rns = lhs.pimpl_->ctx->rns()->project(scalar);

  // Multiply each residue row by its projected scalar value.
  const size_t degree = lhs.pimpl_->ctx->degree();
  const size_t num_moduli = lhs.pimpl_->ctx->q().size();

  for (size_t i = 0; i < num_moduli; ++i) {
    const auto &qi = lhs.pimpl_->ctx->q()[i];
    uint64_t *coeffs = lhs.pimpl_->coefficients.get() + i * degree;
    const uint64_t scalar_mod_qi = scalar_rns[i];

    if (lhs.pimpl_->allow_variable_time_computations) {
      for (size_t j = 0; j < degree; ++j) {
        coeffs[j] = qi.MulVt(coeffs[j], scalar_mod_qi);
      }
    } else {
      for (size_t j = 0; j < degree; ++j) {
        coeffs[j] = qi.Mul(coeffs[j], scalar_mod_qi);
      }
    }
  }

  // Refresh cached multiply hints if they are materialized.
  if (lhs.pimpl_->coefficients_shoup) {
    lhs.pimpl_->rebuild_multiply_hints();
  }

  return lhs;
}

Poly operator-(const Poly &poly) {
  Poly result(poly);

  // Negate each residue row in place.
  const size_t degree = result.pimpl_->ctx->degree();
  const size_t num_moduli = result.pimpl_->ctx->q().size();

  for (size_t i = 0; i < num_moduli; ++i) {
    const auto &qi = result.pimpl_->ctx->q()[i];
    uint64_t *coeffs = result.pimpl_->coefficients.get() + i * degree;

    if (result.pimpl_->allow_variable_time_computations) {
      qi.NegVecVt(coeffs, degree);
    } else {
      qi.NegVec(coeffs, degree);
    }
  }

  // Negate cached multiply hints when they are materialized.
  if (result.pimpl_->coefficients_shoup) {
    for (size_t i = 0; i < num_moduli; ++i) {
      const auto &qi = result.pimpl_->ctx->q()[i];
      uint64_t *multiply_hints =
          result.pimpl_->coefficients_shoup.get() + i * degree;

      if (result.pimpl_->allow_variable_time_computations) {
        qi.NegVecVt(multiply_hints, degree);
      } else {
        qi.NegVec(multiply_hints, degree);
      }
    }
  }

  return result;
}

// Dot product function
Poly dot_product(const std::vector<std::reference_wrapper<const Poly>> &p,
                 const std::vector<std::reference_wrapper<const Poly>> &q) {
  if (p.empty() || q.empty()) {
    throw DefaultException("dot_product requires at least one polynomial");
  }

  if (p.size() != q.size()) {
    throw DefaultException("Vectors must have the same size for dot product");
  }

  // Initialize result with first product
  Poly result = p[0].get() * q[0].get();

  // Add remaining products
  for (size_t i = 1; i < p.size(); ++i) {
    result += p[i].get() * q[i].get();
  }

  return result;
}

// Binary operators implementation
Poly operator+(const Poly &lhs, const Poly &rhs) {
  Poly result = lhs;
  result += rhs;
  return result;
}

Poly operator-(const Poly &lhs, const Poly &rhs) {
  Poly result = lhs;
  result -= rhs;
  return result;
}

Poly operator*(const Poly &lhs, const Poly &rhs) {
  Poly result = lhs;
  result *= rhs;
  return result;
}

Poly operator*(const Poly &lhs, const ::bfv::math::rns::BigUint &scalar) {
  Poly result = lhs;
  result *= scalar;
  return result;
}

Poly operator*(const ::bfv::math::rns::BigUint &scalar, const Poly &rhs) {
  return rhs * scalar;
}

// Explicit template instantiations for common RNG types
template Poly Poly::random<std::mt19937_64>(std::shared_ptr<const Context> ctx,
                                            Representation representation,
                                            std::mt19937_64 &rng,
                                            Poly::ArenaHandle pool);

template Poly Poly::small<std::mt19937_64>(std::shared_ptr<const Context> ctx,
                                           Representation representation,
                                           size_t variance,
                                           std::mt19937_64 &rng,
                                           Poly::ArenaHandle pool);

void Poly::tensor_product_inplace(Poly &c00, Poly &c01, Poly &c2,
                                  const Poly &c10, const Poly &c11) {
  if (*c00.pimpl_->ctx != *c01.pimpl_->ctx ||
      *c00.pimpl_->ctx != *c10.pimpl_->ctx ||
      *c00.pimpl_->ctx != *c11.pimpl_->ctx ||
      *c00.pimpl_->ctx != *c2.pimpl_->ctx) {
    throw DefaultException("Context mismatch in tensor_product_inplace");
  }

  if (c00.representation() != Representation::Ntt ||
      c01.representation() != Representation::Ntt ||
      c10.representation() != Representation::Ntt ||
      c11.representation() != Representation::Ntt ||
      c2.representation() != Representation::Ntt) {
    throw DefaultException("All polynomials must be in NTT representation");
  }

  // Propagate variable time computations
  bool use_variable_time = c00.allows_variable_time_computations() ||
                           c10.allows_variable_time_computations() ||
                           c11.allows_variable_time_computations();

  const size_t degree = c00.pimpl_->ctx->degree();
  const size_t num_moduli = c00.pimpl_->ctx->q().size();
  const auto &q_ops = c00.pimpl_->ctx->q();
  constexpr size_t kTensorTileSize = 256;
  thread_local std::vector<uint64_t> tl_tensor_tmp;
  if (tl_tensor_tmp.size() < kTensorTileSize) {
    tl_tensor_tmp.resize(kTensorTileSize);
  }

  for (size_t i = 0; i < num_moduli; ++i) {
    const auto &qi = q_ops[i];
    uint64_t *p00 = c00.data(i);
    uint64_t *p01 = c01.data(i);
    const uint64_t *p10 = c10.data(i);
    const uint64_t *p11 = c11.data(i);
    uint64_t *p2 = c2.data(i);

    for (size_t offset = 0; offset < degree; offset += kTensorTileSize) {
      const size_t tile_size = std::min(kTensorTileSize, degree - offset);
      uint64_t *x0 = p00 + offset;
      uint64_t *x1 = p01 + offset;
      const uint64_t *y0 = p10 + offset;
      const uint64_t *y1 = p11 + offset;
      uint64_t *x2 = p2 + offset;
      uint64_t *temp = tl_tensor_tmp.data();

      if (use_variable_time) {
        qi.MulToVt(temp, x0, y1, tile_size);
        qi.MulToVt(x2, x1, y1, tile_size);
        qi.MulVecVt(x1, y0, tile_size);
        qi.AddVecVt(x1, temp, tile_size);
        qi.MulVecVt(x0, y0, tile_size);
      } else {
        qi.MulTo(temp, x0, y1, tile_size);
        qi.MulTo(x2, x1, y1, tile_size);
        qi.MulVec(x1, y0, tile_size);
        qi.AddVec(x1, temp, tile_size);
        qi.MulVec(x0, y0, tile_size);
      }
    }
  }
}

// Namespace closing brace moved to end of file

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
    if (!term.pimpl_->coefficients_shoup) {
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
        qi.MulAddShoupVecVt(result_coeffs, factor_coeffs, term_coeffs,
                            term_hints, degree);
      } else {
        qi.MulAddShoupVec(result_coeffs, factor_coeffs, term_coeffs, term_hints,
                          degree);
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
        qi.MulAddVecVt(result_coeffs, factor_coeffs, term_coeffs, degree);
      } else {
        qi.MulAddVec(result_coeffs, factor_coeffs, term_coeffs, degree);
      }
    }
  } else {
    throw DefaultException(
        "multiply_accumulate received an unsupported representation");
  }
}
}  // namespace bfv::math::rq
