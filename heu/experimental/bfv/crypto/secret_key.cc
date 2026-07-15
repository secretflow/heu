#include "crypto/secret_key.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/key_switching_key.h"
#include "crypto/plaintext.h"
#include "crypto/rgsw_ciphertext.h"
#include "math/basis_mapper.h"
#include "math/context.h"
#include "math/modulus.h"
#include "math/ntt_harvey.h"
#include "math/poly.h"
#include "math/representation.h"
#include "math/sample_vec_cbd.h"
#include "math/substitution_exponent.h"
#include "util/profiler.h"

// Serialization includes
#include "crypto/serialization/msgpack_adaptors.h"

namespace crypto {
namespace bfv {

namespace {
using Clock = std::chrono::steady_clock;

inline bool heu_dec_profile_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_DEC_PROFILE");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline int64_t micros_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
      .count();
}

}  // namespace

// SecretKey::Impl - PIMPL implementation
class SecretKey::Impl {
 public:
  std::shared_ptr<BfvParameters> par;
  std::vector<int64_t> coeffs;

  // Simple single-item cache for the most recently used NTT key
  mutable std::shared_ptr<const ::bfv::math::rq::Context> cached_ctx;
  mutable ::bfv::math::rq::Poly cached_ntt_key;
  mutable ::bfv::math::rq::Poly cached_ntt_shoup_key;
  mutable bool cached_ntt_shoup_ready = false;
  mutable std::shared_ptr<const ::bfv::math::rq::Context> cached_square_ctx;
  mutable ::bfv::math::rq::Poly cached_square_ntt_key;
  mutable bool cached_square_ready = false;
  mutable std::shared_ptr<const ::bfv::math::rq::Context>
      cached_substitution_ctx;
  mutable size_t cached_substitution_exponent = 0;
  mutable ::bfv::math::rq::Poly cached_substituted_ntt_key;
  mutable bool cached_substitution_ready = false;

  Impl() = default;

  // Get or create cached NTT key for a specific context
  const ::bfv::math::rq::Poly &get_ntt_key(
      std::shared_ptr<const ::bfv::math::rq::Context> ctx) const {
    // Fast path: check if we have the same context cached
    if (cached_ctx.get() == ctx.get() && cached_ntt_key.ctx()) {
      return cached_ntt_key;  // Return cached copy by ref
    }

    // Slow path: create new NTT key
    auto s = ::bfv::math::rq::Poly::from_i64_vector(
        coeffs, ctx, false, ::bfv::math::rq::Representation::PowerBasis);
    s.change_representation(::bfv::math::rq::Representation::Ntt);

    // Update cache
    cached_ctx = ctx;
    cached_ntt_key = std::move(s);
    cached_ntt_shoup_key = ::bfv::math::rq::Poly();
    cached_ntt_shoup_ready = false;

    return cached_ntt_key;
  }

  const ::bfv::math::rq::Poly &get_ntt_shoup_key(
      std::shared_ptr<const ::bfv::math::rq::Context> ctx) const {
    get_ntt_key(std::move(ctx));
    if (!cached_ntt_shoup_ready) {
      cached_ntt_shoup_key = cached_ntt_key;
      cached_ntt_shoup_key.change_representation(
          ::bfv::math::rq::Representation::NttShoup);
      cached_ntt_shoup_ready = true;
    }
    return cached_ntt_shoup_key;
  }

  const ::bfv::math::rq::Poly &get_square_ntt_key(
      std::shared_ptr<const ::bfv::math::rq::Context> ctx) const {
    if (cached_square_ready && cached_square_ctx.get() == ctx.get() &&
        cached_square_ntt_key.ctx()) {
      return cached_square_ntt_key;
    }

    const auto &s_ntt = get_ntt_key(ctx);
    cached_square_ctx = ctx;
    cached_square_ntt_key = s_ntt * s_ntt;
    cached_square_ready = true;
    return cached_square_ntt_key;
  }

  const ::bfv::math::rq::Poly &get_substituted_ntt_key(
      std::shared_ptr<const ::bfv::math::rq::Context> ctx,
      const ::bfv::math::rq::SubstitutionExponent &exponent) const {
    if (cached_substitution_ready &&
        cached_substitution_ctx.get() == ctx.get() &&
        cached_substitution_exponent == exponent.exponent() &&
        cached_substituted_ntt_key.ctx()) {
      return cached_substituted_ntt_key;
    }

    const auto &s_ntt = get_ntt_key(ctx);
    cached_substitution_ctx = ctx;
    cached_substitution_exponent = exponent.exponent();
    cached_substituted_ntt_key = s_ntt.substitute(exponent);
    cached_substitution_ready = true;
    return cached_substituted_ntt_key;
  }

  // Secure zeroization
  void zeroize() {
    if (!coeffs.empty()) {
      // Securely clear the coefficients
      std::fill(coeffs.begin(), coeffs.end(), 0);
      // Additional security: overwrite memory
      volatile int64_t *ptr = coeffs.data();
      for (size_t i = 0; i < coeffs.size(); ++i) {
        ptr[i] = 0;
      }
    }

    // Clear cached NTT key
    cached_ctx.reset();
    cached_ntt_key = ::bfv::math::rq::Poly();
    cached_ntt_shoup_key = ::bfv::math::rq::Poly();
    cached_ntt_shoup_ready = false;
    cached_square_ctx.reset();
    cached_square_ntt_key = ::bfv::math::rq::Poly();
    cached_square_ready = false;
    cached_substitution_ctx.reset();
    cached_substitution_exponent = 0;
    cached_substituted_ntt_key = ::bfv::math::rq::Poly();
    cached_substitution_ready = false;
  }

  ~Impl() { zeroize(); }
};

// SecretKey implementation
SecretKey::~SecretKey() = default;

SecretKey::SecretKey(SecretKey &&other) noexcept = default;
SecretKey &SecretKey::operator=(SecretKey &&other) noexcept = default;

SecretKey::SecretKey(std::unique_ptr<Impl> impl) : pImpl(std::move(impl)) {}

SecretKey::SecretKey(const std::vector<int64_t> &coeffs,
                     std::shared_ptr<BfvParameters> params) {
  if (!params) {
    throw ParameterException("Parameters cannot be null");
  }

  if (coeffs.size() != params->degree()) {
    throw ParameterException("Coefficient count must match polynomial degree");
  }

  auto impl = std::make_unique<Impl>();
  impl->par = params;
  impl->coeffs = coeffs;

  pImpl = std::move(impl);
}

// Static factory method for std::mt19937_64
SecretKey SecretKey::random(std::shared_ptr<BfvParameters> params,
                            std::mt19937_64 &rng) {
  PROFILE_BLOCK("SK: random");
  if (!params) {
    throw ParameterException("Parameters cannot be null");
  }

  // Generate coefficients using CBD sampling
  auto coeffs = ::bfv::math::utils::sample_vec_cbd(params->degree(),
                                                   params->variance(), rng);

  return SecretKey(coeffs, params);
}

// Static factory method for all-ones secret key (debugging)
SecretKey SecretKey::ones(std::shared_ptr<BfvParameters> params) {
  if (!params) {
    throw ParameterException("Parameters cannot be null");
  }

  // Create coefficients with all 1s
  std::vector<int64_t> coeffs(params->degree(), 1);

  return SecretKey(coeffs, params);
}

// Encryption method with zero noise (debugging)
Ciphertext SecretKey::encrypt_zero_noise(const Plaintext &plaintext) const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }

  if (plaintext.parameters() != parameters()) {
    throw ParameterException("Incompatible BFV parameters");
  }

  // Convert plaintext to polynomial and encrypt with zero noise
  auto poly = plaintext.to_poly();

  try {
    // Get the level from parameters
    auto non_const_ctx =
        std::const_pointer_cast<::bfv::math::rq::Context>(poly.ctx());
    auto level = pImpl->par->level_of_ctx(non_const_ctx);

    // Get the cached secret key polynomial
    const auto &s_poly = pImpl->get_ntt_key(poly.ctx());

    // Create 'a' polynomial with all coefficients = 0 (for debugging)
    auto a = ::bfv::math::rq::Poly::zero(poly.ctx(),
                                         ::bfv::math::rq::Representation::Ntt);

    // Compute a * s
    auto a_s = a * s_poly;

    // Zero error polynomial (no noise)
    auto e = ::bfv::math::rq::Poly::zero(poly.ctx(),
                                         ::bfv::math::rq::Representation::Ntt);

    // Compute b = e - a*s + m = -a*s + m (since e = 0)
    auto b = e;
    b -= a_s;
    b += poly;

    // Enable variable time computations for performance
    a.allow_variable_time_computations();
    b.allow_variable_time_computations();

    b.change_representation(::bfv::math::rq::Representation::PowerBasis);
    a.change_representation(::bfv::math::rq::Representation::PowerBasis);

    // Create ciphertext from polynomials [b, a] with level
    std::vector<::bfv::math::rq::Poly> polynomials;
    polynomials.push_back(std::move(b));
    polynomials.push_back(std::move(a));

    auto ciphertext = Ciphertext::from_polynomials_with_level(
        std::move(polynomials), pImpl->par, level);

    return ciphertext;

  } catch (const std::exception &e) {
    throw MathException("Failed to encrypt with zero noise: " +
                        std::string(e.what()));
  }
}

// Encryption method for std::mt19937_64
Ciphertext SecretKey::encrypt(const Plaintext &plaintext,
                              std::mt19937_64 &rng) const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }

  if (plaintext.parameters() != parameters()) {
    throw ParameterException("Incompatible BFV parameters");
  }

  // Convert plaintext to polynomial and encrypt
  auto poly = plaintext.to_poly();
  return encrypt_poly_impl(poly, rng);
}

// Internal method to encrypt a polynomial directly
Ciphertext SecretKey::encrypt_poly_impl(const ::bfv::math::rq::Poly &poly,
                                        std::mt19937_64 &rng) const {
  PROFILE_BLOCK("SK: encrypt_poly_impl");
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }

  if (poly.representation() != ::bfv::math::rq::Representation::Ntt) {
    throw ParameterException("Polynomial must be in NTT representation");
  }

  try {
    auto non_const_ctx =
        std::const_pointer_cast<::bfv::math::rq::Context>(poly.ctx());
    auto level = pImpl->par->level_of_ctx(non_const_ctx);

    std::array<uint8_t, 32> seed;
    for (size_t offset = 0; offset < seed.size(); offset += sizeof(uint64_t)) {
      uint64_t word = rng();
      std::memcpy(seed.data() + offset, &word, sizeof(uint64_t));
    }

    // Get the cached secret key polynomial
    const auto &s_poly = pImpl->get_ntt_key(poly.ctx());

    // Create random 'a' polynomial from seed
    auto a = ::bfv::math::rq::Poly::random_from_seed(
        poly.ctx(), ::bfv::math::rq::Representation::Ntt, seed);

    // Compute a * s
    auto a_s = a * s_poly;

    // Generate small error polynomial
    auto e = ::bfv::math::rq::Poly::small(poly.ctx(),
                                          ::bfv::math::rq::Representation::Ntt,
                                          pImpl->par->variance(), rng);

    // Compute b = e - a*s + m
    auto b = e;
    b -= a_s;
    b += poly;

    // Enable variable time computations for performance
    a.allow_variable_time_computations();
    b.allow_variable_time_computations();

    b.change_representation(::bfv::math::rq::Representation::PowerBasis);
    a.change_representation(::bfv::math::rq::Representation::PowerBasis);

    // Create ciphertext from polynomials [b, a] with level
    std::vector<::bfv::math::rq::Poly> polynomials;
    polynomials.push_back(std::move(b));
    polynomials.push_back(std::move(a));

    auto ciphertext = Ciphertext::from_polynomials_with_level(
        std::move(polynomials), pImpl->par, level);

    // Set the seed for compressed representation
    ciphertext.set_seed(seed);

    return ciphertext;

  } catch (const std::exception &e) {
    throw MathException("Failed to encrypt: " + std::string(e.what()));
  }
}

// Decryption method
Plaintext SecretKey::decrypt(const Ciphertext &ciphertext,
                             const std::optional<Encoding> &encoding) const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }

  if (ciphertext.parameters() != parameters()) {
    throw ParameterException("Incompatible BFV parameters");
  }

  try {
    // Get the ciphertext polynomials
    const auto &ct_polys = ciphertext.polynomials();
    if (ct_polys.empty()) {
      throw ParameterException("Ciphertext is empty");
    }

    // OPTIMIZED: Use cached NTT secret key reference instead of recreating or
    // copying each time
    auto ctx = ct_polys[0].ctx();
    const auto &s_ntt = pImpl->get_ntt_key(ctx);
    const auto &s_ntt_shoup = pImpl->get_ntt_shoup_key(ctx);

    ::bfv::math::rq::Poly phase_owned;
    ::bfv::math::rq::Poly *phase_ptr = nullptr;
    if (ct_polys.size() == 2) {
      thread_local ::bfv::math::rq::Poly tl_phase;
      if (!tl_phase.ctx() || tl_phase.ctx() != ctx) {
        tl_phase = ::bfv::math::rq::Poly::uninitialized(
            ctx, ::bfv::math::rq::Representation::PowerBasis);
      } else if (tl_phase.representation() !=
                 ::bfv::math::rq::Representation::PowerBasis) {
        tl_phase.override_representation(
            ::bfv::math::rq::Representation::PowerBasis);
      }
      tl_phase.disallow_variable_time_computations();
      phase_ptr = &tl_phase;
    } else {
      phase_owned = ct_polys[0];
      phase_owned.disallow_variable_time_computations();
      if (phase_owned.representation() !=
          ::bfv::math::rq::Representation::PowerBasis) {
        phase_owned.override_representation(
            ::bfv::math::rq::Representation::PowerBasis);
      }
      phase_ptr = &phase_owned;
    }
    auto &phase = *phase_ptr;

    if (ct_polys.size() > 1) {
      if (ct_polys.size() == 2) {
        const auto ct_representation = ct_polys[0].representation();
        if (ct_representation == ::bfv::math::rq::Representation::PowerBasis) {
          const size_t num_moduli = ctx->q().size();
          const size_t degree = ctx->degree();
          const auto &q_ops = ctx->q();
          const auto &ntt_ops = ctx->ops();
          bool use_harvey = true;
          for (size_t m = 0; m < num_moduli; ++m) {
            if (!ntt_ops[m].GetNTTTables()) {
              use_harvey = false;
              break;
            }
          }

          if (use_harvey) {
            for (size_t m = 0; m < num_moduli; ++m) {
              const auto &qi = q_ops[m];
              const auto *tables = ntt_ops[m].GetNTTTables();
              uint64_t *phase_raw = phase.data(m);
              const uint64_t *c0_raw = ct_polys[0].data(m);
              const uint64_t *c1_raw = ct_polys[1].data(m);

              std::copy_n(c1_raw, degree, phase_raw);
              ::bfv::math::ntt::HarveyNTT::HarveyNttLazy(phase_raw, *tables);
              qi.MulShoupVec(phase_raw, s_ntt.data(m),
                             s_ntt_shoup.data_shoup(m), degree);
              ::bfv::math::ntt::HarveyNTT::InverseHarveyNtt(phase_raw, *tables);
              qi.AddVec(phase_raw, c0_raw, degree);
            }
          } else {
            for (size_t m = 0; m < num_moduli; ++m) {
              const auto &qi = q_ops[m];
              const auto &ntt_op = ntt_ops[m];
              uint64_t *phase_raw = phase.data(m);
              const uint64_t *c0_raw = ct_polys[0].data(m);
              const uint64_t *c1_raw = ct_polys[1].data(m);

              std::copy_n(c1_raw, degree, phase_raw);
              ntt_op.ForwardInPlaceLazy(phase_raw);
              qi.MulShoupVec(phase_raw, s_ntt.data(m),
                             s_ntt_shoup.data_shoup(m), degree);
              ntt_op.BackwardInPlace(phase_raw);
              qi.AddVec(phase_raw, c0_raw, degree);
            }
          }
        } else {
          auto dot_phase = ct_polys[1];
          dot_phase.disallow_variable_time_computations();
          if (dot_phase.representation() !=
              ::bfv::math::rq::Representation::Ntt) {
            dot_phase.change_representation(
                ::bfv::math::rq::Representation::Ntt);
          }
          dot_phase *= s_ntt;

          auto c0_term = ct_polys[0];
          c0_term.disallow_variable_time_computations();
          if (c0_term.representation() !=
              ::bfv::math::rq::Representation::Ntt) {
            c0_term.change_representation(::bfv::math::rq::Representation::Ntt);
          }
          dot_phase += c0_term;
          dot_phase.change_representation(
              ::bfv::math::rq::Representation::PowerBasis);
          phase = std::move(dot_phase);
        }
      } else {
        auto dot_phase = ct_polys[1];
        dot_phase.change_representation(::bfv::math::rq::Representation::Ntt);
        dot_phase *= s_ntt;
        auto s_power = s_ntt * s_ntt;
        for (size_t i = 2; i < ct_polys.size(); ++i) {
          auto cis = ct_polys[i];
          cis.change_representation(::bfv::math::rq::Representation::Ntt);
          cis *= s_power;
          dot_phase += cis;
          if (i + 1 < ct_polys.size()) {
            s_power *= s_ntt;
          }
        }
        dot_phase.change_representation(
            ::bfv::math::rq::Representation::PowerBasis);
        phase += dot_phase;
      }
    }

    // Scale down by the scaling factor
    auto mapper = pImpl->par->plaintext_mapper_at_level(ciphertext.level());

    auto scaled_poly = phase.map_to(*mapper);

    // Convert to coefficient vector
    auto coeffs_vec = scaled_poly.to_u64_vector();
    if (coeffs_vec.empty()) {
      throw MathException("Failed to extract coefficients from polynomial");
    }

    uint64_t plaintext_mod = pImpl->par->plaintext_modulus();
    std::vector<uint64_t> v;
    v.reserve(coeffs_vec.size());
    for (uint64_t coeff : coeffs_vec) {
      v.push_back(coeff + plaintext_mod);
    }

    std::vector<uint64_t> w(
        v.begin(), v.begin() + std::min(v.size(), pImpl->par->degree()));
    w.resize(pImpl->par->degree(), 0);

    // NOTE: The scaler output is already mod t (plaintext modulus),
    // so we only need to reduce mod t, not mod q0

    auto plaintext_modulus = ::bfv::math::zq::Modulus::New(plaintext_mod);

    if (plaintext_modulus) {
      for (auto &coeff : w) {
        coeff = plaintext_modulus->Reduce(coeff);
      }
    }

    // Use lightweight constructor: avoid building poly_ntt here
    return Plaintext::from_decrypted_coeffs(w, ciphertext.level(), pImpl->par,
                                            encoding);

  } catch (const std::exception &e) {
    throw MathException("Failed to decrypt: " + std::string(e.what()));
  }
}

// Void overload of decrypt to fill preallocated Plaintext
void SecretKey::decrypt(const Ciphertext &ciphertext, Plaintext &out,
                        const std::optional<Encoding> &encoding) const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }
  if (ciphertext.parameters() != parameters()) {
    throw ParameterException("Incompatible BFV parameters");
  }

  try {
    PROFILE_BLOCK("Dec: Total");
    const bool profile_enabled = heu_dec_profile_enabled();
    const auto total_begin =
        profile_enabled ? Clock::now() : Clock::time_point{};
    int64_t t_dot_us = 0;
    int64_t t_scale_us = 0;
    int64_t t_extract_us = 0;
    int64_t t_reduce_copy_us = 0;

    // Get the ciphertext polynomials
    const auto &ct_polys = ciphertext.polynomials();
    if (ct_polys.empty()) {
      throw ParameterException("Ciphertext is empty");
    }

    // OPTIMIZED: Use cached NTT secret key reference instead of recreating or
    // copying each time
    auto ctx = ct_polys[0].ctx();
    const auto &s_ntt = pImpl->get_ntt_key(ctx);
    const auto &s_ntt_shoup = pImpl->get_ntt_shoup_key(ctx);

    ::bfv::math::rq::Poly phase_owned;
    ::bfv::math::rq::Poly *phase_ptr = nullptr;
    if (ct_polys.size() == 2) {
      thread_local ::bfv::math::rq::Poly tl_phase;
      if (!tl_phase.ctx() || tl_phase.ctx() != ctx) {
        tl_phase = ::bfv::math::rq::Poly::uninitialized(
            ctx, ::bfv::math::rq::Representation::PowerBasis);
      } else if (tl_phase.representation() !=
                 ::bfv::math::rq::Representation::PowerBasis) {
        tl_phase.override_representation(
            ::bfv::math::rq::Representation::PowerBasis);
      }
      tl_phase.disallow_variable_time_computations();
      phase_ptr = &tl_phase;
    } else {
      phase_owned = ct_polys[0];
      phase_owned.disallow_variable_time_computations();
      if (phase_owned.representation() !=
          ::bfv::math::rq::Representation::PowerBasis) {
        phase_owned.override_representation(
            ::bfv::math::rq::Representation::PowerBasis);
      }
      phase_ptr = &phase_owned;
    }
    auto &phase = *phase_ptr;

    if (ct_polys.size() > 1) {
      const auto dot_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      if (ct_polys.size() == 2) {
        PROFILE_BLOCK("Dec: dot");
        const auto ct_representation = ct_polys[0].representation();
        if (ct_representation == ::bfv::math::rq::Representation::PowerBasis) {
          const size_t num_moduli = ctx->q().size();
          const size_t degree = ctx->degree();
          const auto &q_ops = ctx->q();
          const auto &ntt_ops = ctx->ops();
          int64_t t_copy_us = 0;
          int64_t t_ntt_us = 0;
          int64_t t_mul_us = 0;
          int64_t t_intt_us = 0;
          int64_t t_add_us = 0;
          bool use_harvey = true;
          for (size_t m = 0; m < num_moduli; ++m) {
            if (!ntt_ops[m].GetNTTTables()) {
              use_harvey = false;
              break;
            }
          }

          if (use_harvey) {
            for (size_t m = 0; m < num_moduli; ++m) {
              const auto &qi = q_ops[m];
              const auto *tables = ntt_ops[m].GetNTTTables();
              uint64_t *phase_raw = phase.data(m);
              const uint64_t *c0_raw = ct_polys[0].data(m);
              const uint64_t *c1_raw = ct_polys[1].data(m);

              const auto copy_begin =
                  profile_enabled ? Clock::now() : Clock::time_point{};
              std::copy_n(c1_raw, degree, phase_raw);
              if (profile_enabled) {
                t_copy_us += micros_between(copy_begin, Clock::now());
              }

              const auto ntt_begin =
                  profile_enabled ? Clock::now() : Clock::time_point{};
              ::bfv::math::ntt::HarveyNTT::HarveyNttLazy(phase_raw, *tables);
              if (profile_enabled) {
                t_ntt_us += micros_between(ntt_begin, Clock::now());
              }

              const auto mul_begin =
                  profile_enabled ? Clock::now() : Clock::time_point{};
              qi.MulShoupVec(phase_raw, s_ntt.data(m),
                             s_ntt_shoup.data_shoup(m), degree);
              if (profile_enabled) {
                t_mul_us += micros_between(mul_begin, Clock::now());
              }

              const auto intt_begin =
                  profile_enabled ? Clock::now() : Clock::time_point{};
              ::bfv::math::ntt::HarveyNTT::InverseHarveyNtt(phase_raw, *tables);
              if (profile_enabled) {
                t_intt_us += micros_between(intt_begin, Clock::now());
              }

              const auto add_begin =
                  profile_enabled ? Clock::now() : Clock::time_point{};
              qi.AddVec(phase_raw, c0_raw, degree);
              if (profile_enabled) {
                t_add_us += micros_between(add_begin, Clock::now());
              }
            }
          } else {
            for (size_t m = 0; m < num_moduli; ++m) {
              const auto &qi = q_ops[m];
              const auto &ntt_op = ntt_ops[m];
              uint64_t *phase_raw = phase.data(m);
              const uint64_t *c0_raw = ct_polys[0].data(m);
              const uint64_t *c1_raw = ct_polys[1].data(m);

              const auto copy_begin =
                  profile_enabled ? Clock::now() : Clock::time_point{};
              std::copy_n(c1_raw, degree, phase_raw);
              if (profile_enabled) {
                t_copy_us += micros_between(copy_begin, Clock::now());
              }

              const auto ntt_begin =
                  profile_enabled ? Clock::now() : Clock::time_point{};
              ntt_op.ForwardInPlaceLazy(phase_raw);
              if (profile_enabled) {
                t_ntt_us += micros_between(ntt_begin, Clock::now());
              }

              const auto mul_begin =
                  profile_enabled ? Clock::now() : Clock::time_point{};
              qi.MulShoupVec(phase_raw, s_ntt.data(m),
                             s_ntt_shoup.data_shoup(m), degree);
              if (profile_enabled) {
                t_mul_us += micros_between(mul_begin, Clock::now());
              }

              const auto intt_begin =
                  profile_enabled ? Clock::now() : Clock::time_point{};
              ntt_op.BackwardInPlace(phase_raw);
              if (profile_enabled) {
                t_intt_us += micros_between(intt_begin, Clock::now());
              }

              const auto add_begin =
                  profile_enabled ? Clock::now() : Clock::time_point{};
              qi.AddVec(phase_raw, c0_raw, degree);
              if (profile_enabled) {
                t_add_us += micros_between(add_begin, Clock::now());
              }
            }
          }
          if (profile_enabled) {
            std::cerr << "[HEU_DEC_DOT_PROFILE]"
                      << " copy_us=" << t_copy_us << " ntt_us=" << t_ntt_us
                      << " mul_us=" << t_mul_us << " intt_us=" << t_intt_us
                      << " add_us=" << t_add_us << " total_us="
                      << (t_copy_us + t_ntt_us + t_mul_us + t_intt_us +
                          t_add_us)
                      << '\n';
          }
        } else {
          auto dot_phase = ct_polys[1];
          dot_phase.disallow_variable_time_computations();
          if (dot_phase.representation() !=
              ::bfv::math::rq::Representation::Ntt) {
            dot_phase.change_representation(
                ::bfv::math::rq::Representation::Ntt);
          }
          dot_phase *= s_ntt;

          auto c0_term = ct_polys[0];
          c0_term.disallow_variable_time_computations();
          if (c0_term.representation() !=
              ::bfv::math::rq::Representation::Ntt) {
            c0_term.change_representation(::bfv::math::rq::Representation::Ntt);
          }
          dot_phase += c0_term;
          dot_phase.change_representation(
              ::bfv::math::rq::Representation::PowerBasis);
          phase = std::move(dot_phase);
        }
      } else {
        auto dot_phase = ct_polys[1];
        {
          PROFILE_BLOCK("Dec: phase_init");
          dot_phase.disallow_variable_time_computations();
          dot_phase.change_representation(::bfv::math::rq::Representation::Ntt);
          dot_phase *= s_ntt;
        }

        {
          PROFILE_BLOCK("Dec: dot");
          auto s_power = s_ntt * s_ntt;
          for (size_t i = 2; i < ct_polys.size(); ++i) {
            auto cis = ct_polys[i];
            cis.disallow_variable_time_computations();
            cis.change_representation(::bfv::math::rq::Representation::Ntt);
            cis *= s_power;
            dot_phase += cis;

            if (i + 1 < ct_polys.size()) {
              s_power *= s_ntt;
            }
          }
        }

        {
          PROFILE_BLOCK("Dec: to_power");
          dot_phase.change_representation(
              ::bfv::math::rq::Representation::PowerBasis);
          phase += dot_phase;
        }
      }
      if (profile_enabled) {
        t_dot_us = micros_between(dot_begin, Clock::now());
      }
    }

    out.resize_raw(pImpl->par->degree());
    uint64_t *out_data = out.data();

    {
      PROFILE_BLOCK("Dec: scale");
      const auto scale_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      auto mapper = pImpl->par->plaintext_mapper_at_level(ciphertext.level());
      mapper->write_power_basis_u64(phase, out_data);
      if (profile_enabled) {
        t_scale_us = micros_between(scale_begin, Clock::now());
      }
    }

    // Set plaintext metadata
    out.set_metadata(ciphertext.level(), pImpl->par, encoding);
    if (profile_enabled) {
      auto total_us = micros_between(total_begin, Clock::now());
      std::cerr << "[HEU_DEC_PROFILE]"
                << " dot_us=" << t_dot_us << " scale_us=" << t_scale_us
                << " extract_us=" << t_extract_us
                << " reduce_copy_us=" << t_reduce_copy_us
                << " total_us=" << total_us << " ct_size=" << ct_polys.size()
                << '\n';
    }

  } catch (const std::exception &e) {
    throw MathException("Failed to decrypt: " + std::string(e.what()));
  }
}

// Noise measurement (unsafe - variable time)
size_t SecretKey::measure_noise(const Ciphertext &ciphertext) const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }

  if (ciphertext.parameters() != parameters()) {
    throw ParameterException("Incompatible BFV parameters");
  }

  try {
    // Decrypt the ciphertext to get the plaintext
    auto plaintext = decrypt(ciphertext);
    auto m = plaintext.to_poly();

    // Get the ciphertext polynomials
    const auto &ct_polys = ciphertext.polynomials();
    auto ctx = ct_polys[0].ctx();

    // Create secret key polynomial with the ciphertext context
    auto s = ::bfv::math::rq::Poly::from_i64_vector(
        pImpl->coeffs, ctx, false, ::bfv::math::rq::Representation::PowerBasis);
    s.change_representation(::bfv::math::rq::Representation::Ntt);

    // Compute the phase c0 + c1*s + c2*s^2 + ...
    auto phase = ct_polys[0];
    phase.disallow_variable_time_computations();
    phase.change_representation(::bfv::math::rq::Representation::Ntt);

    auto s_power = s;
    for (size_t i = 1; i < ct_polys.size(); ++i) {
      auto term = ct_polys[i];
      term.change_representation(::bfv::math::rq::Representation::Ntt);
      term = term * s_power;
      term.disallow_variable_time_computations();
      phase = phase + term;

      if (i + 1 < ct_polys.size()) {
        s_power = s_power * s;
      }
    }

    // Subtract the message to get the noise
    auto noise_poly = phase - m;
    noise_poly.change_representation(
        ::bfv::math::rq::Representation::PowerBasis);

    // Measure the noise magnitude
    // Measure the noise magnitude
    size_t modulus_count = noise_poly.ctx()->q().size();
    size_t degree = noise_poly.ctx()->degree();

    // Find the maximum coefficient magnitude
    auto ciphertext_modulus = ct_polys[0].ctx()->modulus();
    size_t max_noise = 0;

    // Convert coefficients to BigUint for proper noise calculation
    for (size_t i = 0; i < modulus_count; ++i) {
      const uint64_t *mod_coeffs = noise_poly.data(i);
      for (size_t j = 0; j < degree; ++j) {
        uint64_t coeff = mod_coeffs[j];
        if (coeff > 0) {
          // Create BigUint from coefficient
          auto coeff_biguint = ::bfv::math::rns::BigUint(coeff);
          auto complement = ciphertext_modulus - coeff_biguint;

          // Calculate bits for both coeff and its complement, take minimum
          size_t coeff_bits = coeff_biguint.bits();
          size_t complement_bits = complement.bits();
          size_t noise_bits = std::min(coeff_bits, complement_bits);

          max_noise = std::max(max_noise, noise_bits);
        }
      }
    }

    return max_noise;

  } catch (const std::exception &e) {
    throw MathException("Failed to measure noise: " + std::string(e.what()));
  }
}

// Accessors
std::shared_ptr<BfvParameters> SecretKey::parameters() const {
  return pImpl ? pImpl->par : nullptr;
}

bool SecretKey::empty() const {
  return !pImpl || !pImpl->par || pImpl->coeffs.empty();
}

const std::vector<int64_t> &SecretKey::coefficients() const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }
  return pImpl->coeffs;
}

const ::bfv::math::rq::Poly &SecretKey::cached_ntt_key_at(
    std::shared_ptr<const ::bfv::math::rq::Context> ctx) const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }
  return pImpl->get_ntt_key(std::move(ctx));
}

const ::bfv::math::rq::Poly &SecretKey::cached_square_ntt_key_at(
    std::shared_ptr<const ::bfv::math::rq::Context> ctx) const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }
  return pImpl->get_square_ntt_key(std::move(ctx));
}

const ::bfv::math::rq::Poly &SecretKey::cached_substituted_ntt_key_at(
    std::shared_ptr<const ::bfv::math::rq::Context> ctx,
    const ::bfv::math::rq::SubstitutionExponent &exponent) const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }
  return pImpl->get_substituted_ntt_key(std::move(ctx), exponent);
}

void SecretKey::zeroize() {
  if (pImpl) {
    pImpl->zeroize();
    pImpl.reset();  // Clear the pImpl pointer
  }
}

// RGSW encryption method
RGSWCiphertext SecretKey::encrypt_rgsw(const Plaintext &plaintext,
                                       std::mt19937_64 &rng) const {
  if (!pImpl) {
    throw ParameterException("Secret key is not initialized");
  }

  if (plaintext.parameters() != parameters()) {
    throw ParameterException("Incompatible BFV parameters");
  }

  try {
    size_t level = plaintext.level();
    auto ctx = pImpl->par->ctx_at_level(level);

    // Get the plaintext polynomial in NTT representation
    auto m = plaintext.to_poly();

    // Create secret key polynomial s
    auto m_s = ::bfv::math::rq::Poly::from_i64_vector(
        pImpl->coeffs, ctx, false, ::bfv::math::rq::Representation::PowerBasis);
    m_s.change_representation(::bfv::math::rq::Representation::Ntt);

    // Compute m * s
    m_s = m_s * m;
    m_s.change_representation(::bfv::math::rq::Representation::PowerBasis);

    // Convert m to PowerBasis for key switching key generation
    auto m_power = m;
    m_power.change_representation(::bfv::math::rq::Representation::PowerBasis);

    // Create key switching keys
    auto ksk0 = KeySwitchingKey::create(*this, m_power, level, level, rng);
    auto ksk1 = KeySwitchingKey::create(*this, m_s, level, level, rng);

    // Create RGSW ciphertext using factory method
    return RGSWCiphertext::create_from_keys(std::move(ksk0), std::move(ksk1));

  } catch (const std::exception &e) {
    throw MathException("Failed to encrypt RGSW: " + std::string(e.what()));
  }
}

// Serialization implementation
yacl::Buffer SecretKey::Serialize() const {
  SecretKeyData data;
  data.coeffs = pImpl->coeffs;
  // Serialize parameters
  data.params.polynomial_degree = pImpl->par->degree();
  data.params.plaintext_modulus = pImpl->par->plaintext_modulus();
  data.params.moduli = pImpl->par->moduli();
  data.params.moduli_sizes = pImpl->par->moduli_sizes();
  data.params.variance = pImpl->par->variance();
  return MsgpackSerializer::Serialize(data);
}

void SecretKey::Deserialize(yacl::ByteContainerView in,
                            std::shared_ptr<BfvParameters> params) {
  try {
    auto data = MsgpackSerializer::Deserialize<SecretKeyData>(in);

    // Reconstruct the secret key from coefficients
    auto new_key = SecretKey(data.coeffs, params);

    // Move the new key's impl to this
    pImpl = std::move(new_key.pImpl);
  } catch (const std::exception &e) {
    throw SerializationException("Failed to deserialize SecretKey: " +
                                 std::string(e.what()));
  }
}

SecretKey SecretKey::from_bytes(yacl::ByteContainerView bytes,
                                std::shared_ptr<BfvParameters> params) {
  try {
    auto data = MsgpackSerializer::Deserialize<SecretKeyData>(bytes);

    // Use the coefficients to construct the secret key
    return SecretKey(data.coeffs, params);
  } catch (const std::exception &e) {
    throw SerializationException("Failed to deserialize SecretKey: " +
                                 std::string(e.what()));
  }
}

SecretKey SecretKey::from_coefficients(const std::vector<int64_t> &coeffs,
                                       std::shared_ptr<BfvParameters> params) {
  return SecretKey(coeffs, params);
}

}  // namespace bfv
}  // namespace crypto
