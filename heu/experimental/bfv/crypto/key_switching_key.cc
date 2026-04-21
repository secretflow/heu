#include "crypto/key_switching_key.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/secret_key.h"
#include "math/context.h"
#include "math/modulus.h"
#include "math/ntt_harvey.h"
#include "math/poly.h"
#include "math/representation.h"
#include "math/rns_context.h"
#include "math/sample_vec_cbd.h"

// Serialization includes
#include "crypto/serialization/msgpack_adaptors.h"

namespace crypto {
namespace bfv {

namespace {
using Clock = std::chrono::steady_clock;

inline bool heu_ks_profile_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_KS_PROFILE");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline bool heu_ks_batch_ntt_enabled() {
  static const bool enabled = [] {
    const char *enable_env = std::getenv("HEU_BFV_ENABLE_KS_BATCH_NTT");
    if (enable_env && enable_env[0] != '\0' && enable_env[0] != '0') {
      return true;
    }
    const char *disable_env = std::getenv("HEU_BFV_DISABLE_KS_BATCH_NTT");
    if (disable_env && disable_env[0] != '\0' && disable_env[0] != '0') {
      return false;
    }
    return false;
  }();
  return enabled;
}

inline int64_t micros_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
      .count();
}

void ConvertKeySwitchOutputs(
    ::bfv::math::rq::Poly &c0, ::bfv::math::rq::Poly &c1,
    ::bfv::math::rq::Representation output_representation) {
  using ::bfv::math::rq::Representation;

  if (output_representation == Representation::PowerBasis) {
    auto normalize = [](auto &poly) {
      if (poly.representation() == Representation::NttShoup) {
        poly.change_representation(Representation::Ntt);
      }
    };
    normalize(c0);
    normalize(c1);

    if (c0.representation() == Representation::PowerBasis &&
        c1.representation() == Representation::PowerBasis) {
      return;
    }

    if (c0.representation() != Representation::Ntt ||
        c1.representation() != Representation::Ntt || c0.ctx() != c1.ctx()) {
      c0.change_representation(Representation::PowerBasis);
      c1.change_representation(Representation::PowerBasis);
      return;
    }

    const auto &q_ops = c0.ctx()->q();
    const size_t degree = c0.ctx()->degree();
    const auto &ops = c0.ctx()->ops();
    for (size_t i = 0; i < ops.size(); ++i) {
      const auto *tables = ops[i].GetNTTTables();
      if (tables) {
        ::bfv::math::ntt::HarveyNTT::InverseHarveyNttLazy2(c0.data(i),
                                                           c1.data(i), *tables);
        q_ops[i].LazyReduceVec(c0.data(i), degree);
        q_ops[i].LazyReduceVec(c1.data(i), degree);
      } else {
        ops[i].BackwardInPlace(c0.data(i));
        ops[i].BackwardInPlace(c1.data(i));
      }
    }
    c0.override_representation(Representation::PowerBasis);
    c1.override_representation(Representation::PowerBasis);
    return;
  }

  if (c0.representation() != output_representation) {
    c0.change_representation(output_representation);
  }
  if (c1.representation() != output_representation) {
    c1.change_representation(output_representation);
  }
}

inline void FillConstantNttRowWithSourceIndex(
    const uint64_t *power_basis_coefficients, size_t coefficient_count,
    uint64_t source_modulus_value,
    const ::bfv::math::zq::Modulus &target_modulus,
    const ::bfv::math::ntt::NttOperator &ntt_op, uint64_t *out_row) {
  const size_t copy_len = coefficient_count;
  const uint64_t target_modulus_value = target_modulus.P();

  if (source_modulus_value != 0 &&
      source_modulus_value <= target_modulus_value) {
    std::memcpy(out_row, power_basis_coefficients, copy_len * sizeof(uint64_t));
  } else if (source_modulus_value != 0 &&
             source_modulus_value <
                 (target_modulus_value + target_modulus_value)) {
    std::memcpy(out_row, power_basis_coefficients, copy_len * sizeof(uint64_t));
    target_modulus.LazyReduceVec(out_row, copy_len);
  } else {
    std::memcpy(out_row, power_basis_coefficients, copy_len * sizeof(uint64_t));
    target_modulus.ReduceVec(out_row, copy_len);
  }
  ntt_op.ForwardInPlaceLazy(out_row);
}

inline void FillConstantNttRows4WithSourceIndices(
    const uint64_t *coeff0, const uint64_t *coeff1, const uint64_t *coeff2,
    const uint64_t *coeff3, size_t coefficient_count, uint64_t source_modulus0,
    uint64_t source_modulus1, uint64_t source_modulus2,
    uint64_t source_modulus3, const ::bfv::math::zq::Modulus &target_modulus,
    const ::bfv::math::ntt::NttOperator &ntt_op, uint64_t *row0, uint64_t *row1,
    uint64_t *row2, uint64_t *row3) {
  const uint64_t target_modulus_value = target_modulus.P();
  auto fill_row = [&](const uint64_t *src, uint64_t source_modulus_value,
                      uint64_t *dst) {
    if (source_modulus_value != 0 &&
        source_modulus_value <= target_modulus_value) {
      std::memcpy(dst, src, coefficient_count * sizeof(uint64_t));
    } else if (source_modulus_value != 0 &&
               source_modulus_value <
                   (target_modulus_value + target_modulus_value)) {
      std::memcpy(dst, src, coefficient_count * sizeof(uint64_t));
      target_modulus.LazyReduceVec(dst, coefficient_count);
    } else {
      std::memcpy(dst, src, coefficient_count * sizeof(uint64_t));
      target_modulus.ReduceVec(dst, coefficient_count);
    }
  };

  fill_row(coeff0, source_modulus0, row0);
  fill_row(coeff1, source_modulus1, row1);
  fill_row(coeff2, source_modulus2, row2);
  fill_row(coeff3, source_modulus3, row3);

  if (const auto *tables = ntt_op.GetNTTTables()) {
    ::bfv::math::ntt::HarveyNTT::HarveyNttLazy4(row0, row1, row2, row3,
                                                *tables);
  } else {
    ntt_op.ForwardInPlaceLazy(row0);
    ntt_op.ForwardInPlaceLazy(row1);
    ntt_op.ForwardInPlaceLazy(row2);
    ntt_op.ForwardInPlaceLazy(row3);
  }
}

}  // namespace

// KeySwitchingKey::Impl - PIMPL implementation
class KeySwitchingKey::Impl {
 public:
  std::shared_ptr<BfvParameters> par;
  std::optional<std::array<uint8_t, 32>> seed;
  std::vector<::bfv::math::rq::Poly> c0;
  std::vector<::bfv::math::rq::Poly> c1;
  size_t ciphertext_level;
  std::shared_ptr<::bfv::math::rq::Context> ctx_ciphertext;
  size_t ksk_level;
  std::shared_ptr<::bfv::math::rq::Context> ctx_ksk;
  size_t log_base;

  Impl() : ciphertext_level(0), ksk_level(0), log_base(0) {}

  // Constructor from parameters
  Impl(std::shared_ptr<BfvParameters> params,
       std::optional<std::array<uint8_t, 32>> seed_val,
       std::vector<::bfv::math::rq::Poly> c0_polys,
       std::vector<::bfv::math::rq::Poly> c1_polys, size_t ct_level,
       std::shared_ptr<::bfv::math::rq::Context> ctx_ct, size_t ksk_lvl,
       std::shared_ptr<::bfv::math::rq::Context> ctx_ksk_val,
       size_t log_base_val)
      : par(std::move(params)),
        seed(seed_val),
        c0(std::move(c0_polys)),
        c1(std::move(c1_polys)),
        ciphertext_level(ct_level),
        ctx_ciphertext(std::move(ctx_ct)),
        ksk_level(ksk_lvl),
        ctx_ksk(std::move(ctx_ksk_val)),
        log_base(log_base_val) {}
};

// KeySwitchingKey implementation
KeySwitchingKey::~KeySwitchingKey() = default;

KeySwitchingKey::KeySwitchingKey(const KeySwitchingKey &other)
    : pImpl(std::make_unique<Impl>(*other.pImpl)) {}

KeySwitchingKey &KeySwitchingKey::operator=(const KeySwitchingKey &other) {
  if (this != &other) {
    *pImpl = *other.pImpl;
  }
  return *this;
}

KeySwitchingKey::KeySwitchingKey(KeySwitchingKey &&other) noexcept = default;
KeySwitchingKey &KeySwitchingKey::operator=(KeySwitchingKey &&other) noexcept =
    default;

KeySwitchingKey::KeySwitchingKey(std::unique_ptr<Impl> impl)
    : pImpl(std::move(impl)) {}

// Static factory method
KeySwitchingKey KeySwitchingKey::create(const SecretKey &secret_key,
                                        const ::bfv::math::rq::Poly &from,
                                        size_t ciphertext_level,
                                        size_t ksk_level,
                                        std::mt19937_64 &rng) {
  if (secret_key.empty()) {
    throw ParameterException("Secret key is empty");
  }

  try {
    auto params = secret_key.parameters();

    // Get contexts for the specified levels
    auto ctx_ksk = params->ctx_at_level(ksk_level);
    auto ctx_ciphertext = params->ctx_at_level(ciphertext_level);

    // Verify the 'from' polynomial has the correct context
    if (from.ctx() != ctx_ksk) {
      throw ParameterException("Incorrect context for polynomial from");
    }

    const ::bfv::math::rq::Poly *from_ptr = &from;

    // Generate seed for c1 polynomials
    std::array<uint8_t, 32> seed;
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    for (auto &byte : seed) {
      byte = byte_dist(rng);
    }

    std::vector<::bfv::math::rq::Poly> c0_polys, c1_polys;
    size_t log_base_val = 0;

    // Choose algorithm based on context moduli count
    if (ctx_ksk->moduli().size() == 1) {
      // Use decomposition method for single modulus
      auto modulus = ctx_ksk->moduli()[0];

      // Calculate log_modulus and log_base
      uint64_t next_power_of_two = 1;
      while (next_power_of_two < modulus) {
        next_power_of_two <<= 1;
      }
      size_t log_modulus = 0;
      uint64_t temp = next_power_of_two;
      while (temp > 1) {
        temp >>= 1;
        log_modulus++;
      }
      log_base_val = log_modulus / 2;

      size_t c1_size = (log_modulus + log_base_val - 1) / log_base_val;

      // Generate c1 and c0 using decomposition method
      c1_polys = sample_c1_terms(ctx_ksk, seed, c1_size, true);
      c0_polys = build_c0_terms_decomposed(secret_key, *from_ptr, c1_polys, rng,
                                           log_base_val);

    } else {
      size_t c1_size = ctx_ciphertext->moduli().size();

      // Generate c1 and c0 using standard method
      c1_polys = sample_c1_terms(ctx_ksk, seed, c1_size, true);
      c0_polys = build_c0_terms(secret_key, *from_ptr, c1_polys, rng);
      log_base_val = 0;
    }

    // Create implementation
    auto impl = std::make_unique<Impl>(
        params, seed, std::move(c0_polys), std::move(c1_polys),
        ciphertext_level, ctx_ciphertext, ksk_level, ctx_ksk, log_base_val);

    return KeySwitchingKey(std::move(impl));

  } catch (const std::exception &e) {
    throw MathException("Failed to create key switching key: " +
                        std::string(e.what()));
  }
}

std::vector<::bfv::math::rq::Poly> KeySwitchingKey::sample_c1_terms(
    std::shared_ptr<::bfv::math::rq::Context> ctx,
    const std::array<uint8_t, 32> &seed, size_t size, bool with_shoup) {
  std::vector<::bfv::math::rq::Poly> c1(size);

  std::seed_seq seed_sequence(seed.begin(), seed.end());
  std::mt19937_64 rng(seed_sequence);

  for (size_t i = 0; i < size; ++i) {
    auto a = ::bfv::math::rq::Poly::random(
        ctx,
        with_shoup ? ::bfv::math::rq::Representation::NttShoup
                   : ::bfv::math::rq::Representation::Ntt,
        rng);

    a.allow_variable_time_computations();
    c1[i] = std::move(a);
  }

  return c1;
}

std::vector<::bfv::math::rq::Poly> KeySwitchingKey::build_c0_terms(
    const SecretKey &secret_key, const ::bfv::math::rq::Poly &from,
    const std::vector<::bfv::math::rq::Poly> &c1, std::mt19937_64 &rng) {
  if (c1.empty()) {
    throw MathException("Empty number of c1's");
  }

  size_t size = c1.size();
  auto params = secret_key.parameters();

  auto s = ::bfv::math::rq::Poly::from_i64_vector(
      secret_key.coefficients(), c1[0].ctx(), false,
      ::bfv::math::rq::Representation::PowerBasis);
  s.change_representation(::bfv::math::rq::Representation::Ntt);
  const auto &rns = c1[0].ctx()->rns();
  const auto &garner = rns->garner();
  const bool from_is_power =
      from.representation() == ::bfv::math::rq::Representation::PowerBasis;
  ::bfv::math::rq::Poly from_ntt;
  if (!from_is_power) {
    from_ntt = from;
    from_ntt.disallow_variable_time_computations();
    if (from_ntt.representation() != ::bfv::math::rq::Representation::Ntt) {
      from_ntt.change_representation(::bfv::math::rq::Representation::Ntt);
    }
  }

  std::vector<::bfv::math::rq::Poly> c0(size);

  for (size_t i = 0; i < size; ++i) {
    auto a_s = c1[i];
    a_s.disallow_variable_time_computations();
    a_s.override_representation(::bfv::math::rq::Representation::Ntt);
    a_s *= s;

    auto b = ::bfv::math::rq::Poly::small(
        a_s.ctx(), ::bfv::math::rq::Representation::PowerBasis,
        params->variance(), rng);
    if (from_is_power) {
      a_s.change_representation(::bfv::math::rq::Representation::PowerBasis);
      b -= a_s;
      b += (from * garner[i]);
    } else {
      b.change_representation(::bfv::math::rq::Representation::Ntt);
      b -= a_s;
      b += (from_ntt * garner[i]);
    }
    b.allow_variable_time_computations();
    b.change_representation(::bfv::math::rq::Representation::NttShoup);

    c0[i] = std::move(b);
  }

  return c0;
}

std::vector<::bfv::math::rq::Poly> KeySwitchingKey::build_c0_terms_decomposed(
    const SecretKey &secret_key, const ::bfv::math::rq::Poly &from,
    const std::vector<::bfv::math::rq::Poly> &c1, std::mt19937_64 &rng,
    size_t log_base) {
  if (c1.empty()) {
    throw MathException("Empty number of c1's");
  }

  auto params = secret_key.parameters();

  auto s = ::bfv::math::rq::Poly::from_i64_vector(
      secret_key.coefficients(), c1[0].ctx(), false,
      ::bfv::math::rq::Representation::PowerBasis);
  s.change_representation(::bfv::math::rq::Representation::Ntt);
  const bool from_is_power =
      from.representation() == ::bfv::math::rq::Representation::PowerBasis;
  ::bfv::math::rq::Poly from_ntt;
  if (!from_is_power) {
    from_ntt = from;
    from_ntt.disallow_variable_time_computations();
    if (from_ntt.representation() != ::bfv::math::rq::Representation::Ntt) {
      from_ntt.change_representation(::bfv::math::rq::Representation::Ntt);
    }
  }

  std::vector<::bfv::math::rq::Poly> c0(c1.size());

  for (size_t i = 0; i < c1.size(); ++i) {
    auto a_s = c1[i];
    a_s.disallow_variable_time_computations();
    a_s.override_representation(::bfv::math::rq::Representation::Ntt);
    a_s *= s;

    auto b = ::bfv::math::rq::Poly::small(
        a_s.ctx(), ::bfv::math::rq::Representation::PowerBasis,
        params->variance(), rng);

    uint64_t power_val = 1ULL << (i * log_base);
    auto power_biguint = ::bfv::math::rns::BigUint(power_val);
    if (from_is_power) {
      a_s.change_representation(::bfv::math::rq::Representation::PowerBasis);
      b -= a_s;
      b += (from * power_biguint);
    } else {
      b.change_representation(::bfv::math::rq::Representation::Ntt);
      b -= a_s;
      b += (from_ntt * power_biguint);
    }
    b.allow_variable_time_computations();
    b.change_representation(::bfv::math::rq::Representation::NttShoup);

    c0[i] = std::move(b);
  }

  return c0;
}

std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly>
KeySwitchingKey::key_switch(const ::bfv::math::rq::Poly &poly) const {
  return key_switch(poly, ::bfv::math::rq::Representation::Ntt);
}

std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly>
KeySwitchingKey::key_switch(
    const ::bfv::math::rq::Poly &poly,
    ::bfv::math::rq::Representation output_representation) const {
  ::bfv::math::rq::Poly c0;
  ::bfv::math::rq::Poly c1;
  apply_key_switch_into(poly, c0, c1, output_representation);
  return std::make_pair(std::move(c0), std::move(c1));
}

void KeySwitchingKey::apply_key_switch_into(
    const ::bfv::math::rq::Poly &poly, ::bfv::math::rq::Poly &c0,
    ::bfv::math::rq::Poly &c1,
    ::bfv::math::rq::Representation output_representation) const {
  const bool profile_enabled = heu_ks_profile_enabled();
  const auto total_begin = profile_enabled ? Clock::now() : Clock::time_point{};
  int64_t t_prepare_constant_ntt_us = 0;
  int64_t t_mul_accum_us = 0;
  int64_t t_output_us = 0;

  if (!pImpl) {
    throw ParameterException("Key switching key is not initialized");
  }

  // Use decomposition method if log_base is set
  if (pImpl->log_base != 0) {
    auto out = key_switch_decomposed(poly, output_representation);
    c0 = std::move(out.first);
    c1 = std::move(out.second);
    return;
  }

  if (poly.ctx() != pImpl->ctx_ciphertext) {
    throw ParameterException(
        "Input polynomial context does not match the key-switch source "
        "context");
  }

  if (poly.representation() != ::bfv::math::rq::Representation::PowerBasis) {
    throw ParameterException("Incorrect representation");
  }

  size_t max_iterations =
      std::min({poly.ctx()->q().size(), pImpl->c0.size(), pImpl->c1.size()});
  if (max_iterations == 0) {
    c0 = ::bfv::math::rq::Poly::zero(pImpl->ctx_ksk,
                                     ::bfv::math::rq::Representation::Ntt);
    c1 = ::bfv::math::rq::Poly::zero(pImpl->ctx_ksk,
                                     ::bfv::math::rq::Representation::Ntt);
    c0.allow_variable_time_computations();
    c1.allow_variable_time_computations();
    ConvertKeySwitchOutputs(c0, c1, output_representation);
    return;
  }

  if (!c0.ctx() || c0.ctx() != pImpl->ctx_ksk ||
      c0.representation() != ::bfv::math::rq::Representation::Ntt) {
    c0 = ::bfv::math::rq::Poly::uninitialized(
        pImpl->ctx_ksk, ::bfv::math::rq::Representation::Ntt);
  } else {
    c0.override_representation(::bfv::math::rq::Representation::Ntt);
  }
  if (!c1.ctx() || c1.ctx() != pImpl->ctx_ksk ||
      c1.representation() != ::bfv::math::rq::Representation::Ntt) {
    c1 = ::bfv::math::rq::Poly::uninitialized(
        pImpl->ctx_ksk, ::bfv::math::rq::Representation::Ntt);
  } else {
    c1.override_representation(::bfv::math::rq::Representation::Ntt);
  }
  c0.allow_variable_time_computations();
  c1.allow_variable_time_computations();
  const bool batch_ntt_enabled = heu_ks_batch_ntt_enabled();
  if (batch_ntt_enabled) {
    const size_t coeff_count =
        pImpl->ctx_ksk->q().size() * pImpl->ctx_ksk->degree();
    std::fill_n(c0.data(0), coeff_count, uint64_t{0});
    std::fill_n(c1.data(0), coeff_count, uint64_t{0});
  }

  if (batch_ntt_enabled) {
    thread_local ::bfv::math::rq::Poly tl_operand_ntt;
    if (!tl_operand_ntt.ctx() || tl_operand_ntt.ctx() != pImpl->ctx_ksk ||
        tl_operand_ntt.representation() !=
            ::bfv::math::rq::Representation::Ntt) {
      tl_operand_ntt = ::bfv::math::rq::Poly::uninitialized(
          pImpl->ctx_ksk, ::bfv::math::rq::Representation::Ntt);
    } else {
      tl_operand_ntt.override_representation(
          ::bfv::math::rq::Representation::Ntt);
    }

    size_t i = 0;
    thread_local ::bfv::math::rq::Poly tl_operand_ntt0;
    thread_local ::bfv::math::rq::Poly tl_operand_ntt1;
    thread_local ::bfv::math::rq::Poly tl_operand_ntt2;
    thread_local ::bfv::math::rq::Poly tl_operand_ntt3;
    auto ensure_operand = [&](::bfv::math::rq::Poly &operand) {
      if (!operand.ctx() || operand.ctx() != pImpl->ctx_ksk ||
          operand.representation() != ::bfv::math::rq::Representation::Ntt) {
        operand = ::bfv::math::rq::Poly::uninitialized(
            pImpl->ctx_ksk, ::bfv::math::rq::Representation::Ntt);
      } else {
        operand.override_representation(::bfv::math::rq::Representation::Ntt);
      }
    };
    ensure_operand(tl_operand_ntt0);
    ensure_operand(tl_operand_ntt1);
    ensure_operand(tl_operand_ntt2);
    ensure_operand(tl_operand_ntt3);

    for (; i + 3 < max_iterations; i += 4) {
      const auto prepare_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      ::bfv::math::rq::Poly::
          fill_constant_ntt_polynomial4_with_lazy_coefficients_and_variable_time(
              poly.data(i), poly.data(i + 1), poly.data(i + 2),
              poly.data(i + 3), poly.ctx()->degree(), i, i + 1, i + 2, i + 3,
              tl_operand_ntt0, tl_operand_ntt1, tl_operand_ntt2,
              tl_operand_ntt3);
      if (profile_enabled) {
        t_prepare_constant_ntt_us +=
            micros_between(prepare_begin, Clock::now());
      }

      const auto mul_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      c0.multiply_accumulate(tl_operand_ntt0, pImpl->c0[i]);
      c1.multiply_accumulate(tl_operand_ntt0, pImpl->c1[i]);
      c0.multiply_accumulate(tl_operand_ntt1, pImpl->c0[i + 1]);
      c1.multiply_accumulate(tl_operand_ntt1, pImpl->c1[i + 1]);
      c0.multiply_accumulate(tl_operand_ntt2, pImpl->c0[i + 2]);
      c1.multiply_accumulate(tl_operand_ntt2, pImpl->c1[i + 2]);
      c0.multiply_accumulate(tl_operand_ntt3, pImpl->c0[i + 3]);
      c1.multiply_accumulate(tl_operand_ntt3, pImpl->c1[i + 3]);
      if (profile_enabled) {
        t_mul_accum_us += micros_between(mul_begin, Clock::now());
      }
    }
    for (; i < max_iterations; ++i) {
      const auto prepare_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      ::bfv::math::rq::Poly::
          fill_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
              poly.data(i), poly.ctx()->degree(), i, tl_operand_ntt);
      if (profile_enabled) {
        t_prepare_constant_ntt_us +=
            micros_between(prepare_begin, Clock::now());
      }

      const auto mul_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      c0.multiply_accumulate(tl_operand_ntt, pImpl->c0[i]);
      c1.multiply_accumulate(tl_operand_ntt, pImpl->c1[i]);
      if (profile_enabled) {
        t_mul_accum_us += micros_between(mul_begin, Clock::now());
      }
    }
  } else {
    const auto degree = pImpl->ctx_ksk->degree();
    const auto &key_moduli = pImpl->ctx_ksk->q();
    const auto &key_ntt_ops = pImpl->ctx_ksk->ops();
    const auto &source_moduli = poly.ctx()->q();
    const bool use_variable_time = c0.allows_variable_time_computations();

    thread_local std::vector<uint64_t> tl_operand_ntt_rows;
    if (tl_operand_ntt_rows.size() < degree * 4) {
      tl_operand_ntt_rows.resize(degree * 4);
    }
    uint64_t *operand_ntt_row = tl_operand_ntt_rows.data();
    uint64_t *operand_ntt_row1 = operand_ntt_row + degree;
    uint64_t *operand_ntt_row2 = operand_ntt_row1 + degree;
    uint64_t *operand_ntt_row3 = operand_ntt_row2 + degree;

    for (size_t mod_idx = 0; mod_idx < key_moduli.size(); ++mod_idx) {
      uint64_t *out0 = c0.data(mod_idx);
      uint64_t *out1 = c1.data(mod_idx);
      const auto &qi = key_moduli[mod_idx];
      const auto &ntt_op = key_ntt_ops[mod_idx];
      const bool reduce_opt_enabled = qi.SupportsOpt();
      auto reduce_accumulator = [&](__uint128_t acc) {
        if (reduce_opt_enabled) {
          return use_variable_time ? qi.ReduceOptU128Vt(acc)
                                   : qi.ReduceOptU128(acc);
        }
        return use_variable_time ? qi.ReduceU128Vt(static_cast<__int128>(acc))
                                 : qi.ReduceU128(acc);
      };
      auto init_mul_into = [&](uint64_t *dst, const uint64_t *operand,
                               const uint64_t *key, const uint64_t *key_shoup) {
        if (use_variable_time) {
          size_t coeff_idx = 0;
          for (; coeff_idx + 7 < degree; coeff_idx += 8) {
            dst[coeff_idx] = qi.MulShoupVt(operand[coeff_idx], key[coeff_idx],
                                           key_shoup[coeff_idx]);
            dst[coeff_idx + 1] =
                qi.MulShoupVt(operand[coeff_idx + 1], key[coeff_idx + 1],
                              key_shoup[coeff_idx + 1]);
            dst[coeff_idx + 2] =
                qi.MulShoupVt(operand[coeff_idx + 2], key[coeff_idx + 2],
                              key_shoup[coeff_idx + 2]);
            dst[coeff_idx + 3] =
                qi.MulShoupVt(operand[coeff_idx + 3], key[coeff_idx + 3],
                              key_shoup[coeff_idx + 3]);
            dst[coeff_idx + 4] =
                qi.MulShoupVt(operand[coeff_idx + 4], key[coeff_idx + 4],
                              key_shoup[coeff_idx + 4]);
            dst[coeff_idx + 5] =
                qi.MulShoupVt(operand[coeff_idx + 5], key[coeff_idx + 5],
                              key_shoup[coeff_idx + 5]);
            dst[coeff_idx + 6] =
                qi.MulShoupVt(operand[coeff_idx + 6], key[coeff_idx + 6],
                              key_shoup[coeff_idx + 6]);
            dst[coeff_idx + 7] =
                qi.MulShoupVt(operand[coeff_idx + 7], key[coeff_idx + 7],
                              key_shoup[coeff_idx + 7]);
          }
          for (; coeff_idx < degree; ++coeff_idx) {
            dst[coeff_idx] = qi.MulShoupVt(operand[coeff_idx], key[coeff_idx],
                                           key_shoup[coeff_idx]);
          }
        } else {
          size_t coeff_idx = 0;
          for (; coeff_idx + 7 < degree; coeff_idx += 8) {
            dst[coeff_idx] = qi.MulShoup(operand[coeff_idx], key[coeff_idx],
                                         key_shoup[coeff_idx]);
            dst[coeff_idx + 1] =
                qi.MulShoup(operand[coeff_idx + 1], key[coeff_idx + 1],
                            key_shoup[coeff_idx + 1]);
            dst[coeff_idx + 2] =
                qi.MulShoup(operand[coeff_idx + 2], key[coeff_idx + 2],
                            key_shoup[coeff_idx + 2]);
            dst[coeff_idx + 3] =
                qi.MulShoup(operand[coeff_idx + 3], key[coeff_idx + 3],
                            key_shoup[coeff_idx + 3]);
            dst[coeff_idx + 4] =
                qi.MulShoup(operand[coeff_idx + 4], key[coeff_idx + 4],
                            key_shoup[coeff_idx + 4]);
            dst[coeff_idx + 5] =
                qi.MulShoup(operand[coeff_idx + 5], key[coeff_idx + 5],
                            key_shoup[coeff_idx + 5]);
            dst[coeff_idx + 6] =
                qi.MulShoup(operand[coeff_idx + 6], key[coeff_idx + 6],
                            key_shoup[coeff_idx + 6]);
            dst[coeff_idx + 7] =
                qi.MulShoup(operand[coeff_idx + 7], key[coeff_idx + 7],
                            key_shoup[coeff_idx + 7]);
          }
          for (; coeff_idx < degree; ++coeff_idx) {
            dst[coeff_idx] = qi.MulShoup(operand[coeff_idx], key[coeff_idx],
                                         key_shoup[coeff_idx]);
          }
        }
      };
      auto mul_add_into = [&](uint64_t *dst, const uint64_t *operand,
                              const uint64_t *key, const uint64_t *key_shoup) {
        if (use_variable_time) {
          qi.MulAddShoupVecVt(dst, operand, key, key_shoup, degree);
        } else {
          qi.MulAddShoupVec(dst, operand, key, key_shoup, degree);
        }
      };
      auto fused_mul_accumulate4_into =
          [&](bool initialize, const uint64_t *operand0,
              const uint64_t *operand1, const uint64_t *operand2,
              const uint64_t *operand3, const uint64_t *key00,
              const uint64_t *key01, const uint64_t *key02,
              const uint64_t *key03, const uint64_t *key10,
              const uint64_t *key11, const uint64_t *key12,
              const uint64_t *key13) {
            size_t coeff_idx = 0;
            for (; coeff_idx + 3 < degree; coeff_idx += 4) {
              for (size_t lane = 0; lane < 4; ++lane) {
                const size_t idx = coeff_idx + lane;
                __uint128_t acc0 = initialize ? 0 : out0[idx];
                __uint128_t acc1 = initialize ? 0 : out1[idx];
                acc0 += static_cast<__uint128_t>(operand0[idx]) * key00[idx];
                acc0 += static_cast<__uint128_t>(operand1[idx]) * key01[idx];
                acc0 += static_cast<__uint128_t>(operand2[idx]) * key02[idx];
                acc0 += static_cast<__uint128_t>(operand3[idx]) * key03[idx];
                acc1 += static_cast<__uint128_t>(operand0[idx]) * key10[idx];
                acc1 += static_cast<__uint128_t>(operand1[idx]) * key11[idx];
                acc1 += static_cast<__uint128_t>(operand2[idx]) * key12[idx];
                acc1 += static_cast<__uint128_t>(operand3[idx]) * key13[idx];
                out0[idx] = reduce_accumulator(acc0);
                out1[idx] = reduce_accumulator(acc1);
              }
            }
            for (; coeff_idx < degree; ++coeff_idx) {
              __uint128_t acc0 = initialize ? 0 : out0[coeff_idx];
              __uint128_t acc1 = initialize ? 0 : out1[coeff_idx];
              acc0 += static_cast<__uint128_t>(operand0[coeff_idx]) *
                      key00[coeff_idx];
              acc0 += static_cast<__uint128_t>(operand1[coeff_idx]) *
                      key01[coeff_idx];
              acc0 += static_cast<__uint128_t>(operand2[coeff_idx]) *
                      key02[coeff_idx];
              acc0 += static_cast<__uint128_t>(operand3[coeff_idx]) *
                      key03[coeff_idx];
              acc1 += static_cast<__uint128_t>(operand0[coeff_idx]) *
                      key10[coeff_idx];
              acc1 += static_cast<__uint128_t>(operand1[coeff_idx]) *
                      key11[coeff_idx];
              acc1 += static_cast<__uint128_t>(operand2[coeff_idx]) *
                      key12[coeff_idx];
              acc1 += static_cast<__uint128_t>(operand3[coeff_idx]) *
                      key13[coeff_idx];
              out0[coeff_idx] = reduce_accumulator(acc0);
              out1[coeff_idx] = reduce_accumulator(acc1);
            }
          };

      const auto mul_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      size_t src_idx = 0;
      if (src_idx + 3 < max_iterations) {
        const auto prepare_begin =
            profile_enabled ? Clock::now() : Clock::time_point{};
        FillConstantNttRows4WithSourceIndices(
            poly.data(src_idx), poly.data(src_idx + 1), poly.data(src_idx + 2),
            poly.data(src_idx + 3), degree, source_moduli[src_idx].P(),
            source_moduli[src_idx + 1].P(), source_moduli[src_idx + 2].P(),
            source_moduli[src_idx + 3].P(), qi, ntt_op, operand_ntt_row,
            operand_ntt_row1, operand_ntt_row2, operand_ntt_row3);
        if (profile_enabled) {
          t_prepare_constant_ntt_us +=
              micros_between(prepare_begin, Clock::now());
        }

        const uint64_t *key00 = pImpl->c0[src_idx].data(mod_idx);
        const uint64_t *key01 = pImpl->c0[src_idx + 1].data(mod_idx);
        const uint64_t *key02 = pImpl->c0[src_idx + 2].data(mod_idx);
        const uint64_t *key03 = pImpl->c0[src_idx + 3].data(mod_idx);
        const uint64_t *key10 = pImpl->c1[src_idx].data(mod_idx);
        const uint64_t *key11 = pImpl->c1[src_idx + 1].data(mod_idx);
        const uint64_t *key12 = pImpl->c1[src_idx + 2].data(mod_idx);
        const uint64_t *key13 = pImpl->c1[src_idx + 3].data(mod_idx);

        fused_mul_accumulate4_into(true, operand_ntt_row, operand_ntt_row1,
                                   operand_ntt_row2, operand_ntt_row3, key00,
                                   key01, key02, key03, key10, key11, key12,
                                   key13);
        src_idx += 4;
      } else if (src_idx < max_iterations) {
        const auto prepare_begin =
            profile_enabled ? Clock::now() : Clock::time_point{};
        FillConstantNttRowWithSourceIndex(poly.data(src_idx), degree,
                                          source_moduli[src_idx].P(), qi,
                                          ntt_op, operand_ntt_row);
        if (profile_enabled) {
          t_prepare_constant_ntt_us +=
              micros_between(prepare_begin, Clock::now());
        }

        const uint64_t *key0 = pImpl->c0[src_idx].data(mod_idx);
        const uint64_t *key0_shoup = pImpl->c0[src_idx].data_shoup(mod_idx);
        const uint64_t *key1 = pImpl->c1[src_idx].data(mod_idx);
        const uint64_t *key1_shoup = pImpl->c1[src_idx].data_shoup(mod_idx);

        init_mul_into(out0, operand_ntt_row, key0, key0_shoup);
        init_mul_into(out1, operand_ntt_row, key1, key1_shoup);
        ++src_idx;
      }

      for (; src_idx + 3 < max_iterations; src_idx += 4) {
        const auto prepare_begin =
            profile_enabled ? Clock::now() : Clock::time_point{};
        FillConstantNttRows4WithSourceIndices(
            poly.data(src_idx), poly.data(src_idx + 1), poly.data(src_idx + 2),
            poly.data(src_idx + 3), degree, source_moduli[src_idx].P(),
            source_moduli[src_idx + 1].P(), source_moduli[src_idx + 2].P(),
            source_moduli[src_idx + 3].P(), qi, ntt_op, operand_ntt_row,
            operand_ntt_row1, operand_ntt_row2, operand_ntt_row3);
        if (profile_enabled) {
          t_prepare_constant_ntt_us +=
              micros_between(prepare_begin, Clock::now());
        }

        const uint64_t *key00 = pImpl->c0[src_idx].data(mod_idx);
        const uint64_t *key01 = pImpl->c0[src_idx + 1].data(mod_idx);
        const uint64_t *key02 = pImpl->c0[src_idx + 2].data(mod_idx);
        const uint64_t *key03 = pImpl->c0[src_idx + 3].data(mod_idx);
        const uint64_t *key10 = pImpl->c1[src_idx].data(mod_idx);
        const uint64_t *key11 = pImpl->c1[src_idx + 1].data(mod_idx);
        const uint64_t *key12 = pImpl->c1[src_idx + 2].data(mod_idx);
        const uint64_t *key13 = pImpl->c1[src_idx + 3].data(mod_idx);

        fused_mul_accumulate4_into(false, operand_ntt_row, operand_ntt_row1,
                                   operand_ntt_row2, operand_ntt_row3, key00,
                                   key01, key02, key03, key10, key11, key12,
                                   key13);
      }

      for (; src_idx < max_iterations; ++src_idx) {
        const auto prepare_begin =
            profile_enabled ? Clock::now() : Clock::time_point{};
        FillConstantNttRowWithSourceIndex(poly.data(src_idx), degree,
                                          source_moduli[src_idx].P(), qi,
                                          ntt_op, operand_ntt_row);
        if (profile_enabled) {
          t_prepare_constant_ntt_us +=
              micros_between(prepare_begin, Clock::now());
        }

        const uint64_t *key0 = pImpl->c0[src_idx].data(mod_idx);
        const uint64_t *key0_shoup = pImpl->c0[src_idx].data_shoup(mod_idx);
        const uint64_t *key1 = pImpl->c1[src_idx].data(mod_idx);
        const uint64_t *key1_shoup = pImpl->c1[src_idx].data_shoup(mod_idx);

        mul_add_into(out0, operand_ntt_row, key0, key0_shoup);
        mul_add_into(out1, operand_ntt_row, key1, key1_shoup);
      }
      if (profile_enabled) {
        t_mul_accum_us += micros_between(mul_begin, Clock::now());
      }
    }
  }

  const auto output_begin =
      profile_enabled ? Clock::now() : Clock::time_point{};
  ConvertKeySwitchOutputs(c0, c1, output_representation);
  if (profile_enabled) {
    t_output_us = micros_between(output_begin, Clock::now());
    const auto total_us = micros_between(total_begin, Clock::now());
    std::cerr << "[HEU_KS_PROFILE]"
              << " prepare_constant_ntt_us=" << t_prepare_constant_ntt_us
              << " mul_accum_us=" << t_mul_accum_us
              << " output_us=" << t_output_us << " total_us=" << total_us
              << '\n';
  }
}

std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly>
KeySwitchingKey::key_switch_decomposed(
    const ::bfv::math::rq::Poly &poly) const {
  return key_switch_decomposed(poly, ::bfv::math::rq::Representation::Ntt);
}

std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly>
KeySwitchingKey::key_switch_decomposed(
    const ::bfv::math::rq::Poly &poly,
    ::bfv::math::rq::Representation output_representation) const {
  // Validate input polynomial
  if (poly.ctx() != pImpl->ctx_ciphertext) {
    throw ParameterException(
        "Input polynomial context does not match the key-switch source "
        "context");
  }

  if (poly.representation() != ::bfv::math::rq::Representation::PowerBasis) {
    throw ParameterException("Incorrect representation");
  }

  auto modulus = poly.ctx()->moduli()[0];
  uint64_t next_power_of_two = 1;
  while (next_power_of_two < modulus) {
    next_power_of_two <<= 1;
  }
  size_t log_modulus = 0;
  uint64_t temp = next_power_of_two;
  while (temp > 1) {
    temp >>= 1;
    log_modulus++;
  }

  auto poly_coeffs = poly.to_u64_vector();
  std::vector<std::vector<uint64_t>> c2i;

  uint64_t mask = (1ULL << pImpl->log_base) - 1;
  size_t num_parts = (log_modulus + pImpl->log_base - 1) / pImpl->log_base;

  for (size_t part = 0; part < num_parts; ++part) {
    std::vector<uint64_t> part_coeffs;
    part_coeffs.reserve(poly_coeffs.size());

    for (uint64_t coeff : poly_coeffs) {
      part_coeffs.push_back(coeff & mask);
    }
    c2i.push_back(std::move(part_coeffs));

    // Shift coefficients for next part
    for (auto &coeff : poly_coeffs) {
      coeff >>= pImpl->log_base;
    }
  }

  // Initialize result polynomials
  auto c0 = ::bfv::math::rq::Poly::zero(pImpl->ctx_ksk,
                                        ::bfv::math::rq::Representation::Ntt);
  auto c1 = ::bfv::math::rq::Poly::zero(pImpl->ctx_ksk,
                                        ::bfv::math::rq::Representation::Ntt);
  c0.allow_variable_time_computations();
  c1.allow_variable_time_computations();

  // Perform key switching for each decomposed part
  size_t max_iterations =
      std::min({c2i.size(), pImpl->c0.size(), pImpl->c1.size()});

  // Verify decomposition correctness
  auto reconstructed = ::bfv::math::rq::Poly::zero(
      pImpl->ctx_ksk, ::bfv::math::rq::Representation::PowerBasis);
  for (size_t i = 0; i < c2i.size(); ++i) {
    uint64_t power_val = 1ULL << (i * pImpl->log_base);
    auto power_biguint = ::bfv::math::rns::BigUint(power_val);
    auto part = ::bfv::math::rq::Poly::from_u64_vector(
        c2i[i], pImpl->ctx_ksk, false,
        ::bfv::math::rq::Representation::PowerBasis);
    auto scaled_part = part * power_biguint;
    reconstructed = reconstructed + scaled_part;
  }

  auto original_coeffs = poly.to_u64_vector();
  auto reconstructed_coeffs = reconstructed.to_u64_vector();
  [[maybe_unused]] bool decomposition_correct =
      (original_coeffs == reconstructed_coeffs);

  for (size_t i = 0; i < max_iterations; ++i) {
    const auto &c2_i_coefficients = c2i[i];
    const auto &c0_i = pImpl->c0[i];
    const auto &c1_i = pImpl->c1[i];

    auto c2_i = ::bfv::math::rq::Poly::
        create_constant_ntt_polynomial_with_lazy_coefficients_and_variable_time(
            c2_i_coefficients.data(), c2_i_coefficients.size(), pImpl->ctx_ksk);

    c0.multiply_accumulate(c2_i, c0_i);
    c1.multiply_accumulate(c2_i, c1_i);
  }

  ConvertKeySwitchOutputs(c0, c1, output_representation);
  return std::make_pair(std::move(c0), std::move(c1));
}

// Accessors
std::shared_ptr<BfvParameters> KeySwitchingKey::parameters() const {
  return pImpl ? pImpl->par : nullptr;
}

bool KeySwitchingKey::empty() const {
  return !pImpl || !pImpl->par || pImpl->c0.empty() || pImpl->c1.empty();
}

size_t KeySwitchingKey::ciphertext_level() const {
  return pImpl ? pImpl->ciphertext_level : 0;
}

size_t KeySwitchingKey::ksk_level() const {
  return pImpl ? pImpl->ksk_level : 0;
}

size_t KeySwitchingKey::log_base() const { return pImpl ? pImpl->log_base : 0; }

std::optional<std::array<uint8_t, 32>> KeySwitchingKey::seed() const {
  return pImpl ? pImpl->seed : std::nullopt;
}

// Equality operators
bool KeySwitchingKey::operator==(const KeySwitchingKey &other) const {
  if (!pImpl && !other.pImpl) return true;
  if (!pImpl || !other.pImpl) return false;

  // Compare basic parameters first
  if (pImpl->par != other.pImpl->par || pImpl->seed != other.pImpl->seed ||
      pImpl->ciphertext_level != other.pImpl->ciphertext_level ||
      pImpl->ksk_level != other.pImpl->ksk_level ||
      pImpl->log_base != other.pImpl->log_base) {
    return false;
  }

  // Compare c0 and c1 polynomials
  if (pImpl->c0.size() != other.pImpl->c0.size() ||
      pImpl->c1.size() != other.pImpl->c1.size()) {
    return false;
  }

  // Compare each c0 polynomial
  for (size_t i = 0; i < pImpl->c0.size(); ++i) {
    if (pImpl->c0[i] != other.pImpl->c0[i]) {
      return false;
    }
  }

  // Compare each c1 polynomial
  for (size_t i = 0; i < pImpl->c1.size(); ++i) {
    if (pImpl->c1[i] != other.pImpl->c1[i]) {
      return false;
    }
  }

  return true;
}

bool KeySwitchingKey::operator!=(const KeySwitchingKey &other) const {
  return !(*this == other);
}

// Arithmetic operations
KeySwitchingKey KeySwitchingKey::operator+(const KeySwitchingKey &other) const {
  if (!pImpl || !other.pImpl) {
    throw ParameterException("KeySwitchingKey is not initialized");
  }

  // Check parameter compatibility
  if (pImpl->par != other.pImpl->par) {
    throw ParameterException("KeySwitchingKeys have incompatible parameters");
  }

  if (pImpl->ciphertext_level != other.pImpl->ciphertext_level ||
      pImpl->ksk_level != other.pImpl->ksk_level) {
    throw ParameterException("KeySwitchingKeys have incompatible levels");
  }

  if (pImpl->c0.size() != other.pImpl->c0.size() ||
      pImpl->c1.size() != other.pImpl->c1.size()) {
    throw ParameterException("KeySwitchingKeys have incompatible sizes");
  }

  // Add c0 polynomials component-wise
  std::vector<::bfv::math::rq::Poly> c0_sum;
  c0_sum.reserve(pImpl->c0.size());
  for (size_t i = 0; i < pImpl->c0.size(); ++i) {
    c0_sum.push_back(pImpl->c0[i] + other.pImpl->c0[i]);
  }

  // Add c1 polynomials component-wise
  std::vector<::bfv::math::rq::Poly> c1_sum;
  c1_sum.reserve(pImpl->c1.size());
  for (size_t i = 0; i < pImpl->c1.size(); ++i) {
    c1_sum.push_back(pImpl->c1[i] + other.pImpl->c1[i]);
  }

  // Create new KeySwitchingKey from the sum
  std::optional<std::array<uint8_t, 32>> seed;  // No seed for sum
  return KeySwitchingKey::from_components(
      pImpl->par, seed, std::move(c0_sum), std::move(c1_sum),
      pImpl->ciphertext_level, pImpl->ksk_level, pImpl->log_base);
}

// Accessor methods for serialization
const std::vector<::bfv::math::rq::Poly> &KeySwitchingKey::c0_polynomials()
    const {
  if (!pImpl) {
    throw ParameterException("KeySwitchingKey is not initialized");
  }
  return pImpl->c0;
}

const std::vector<::bfv::math::rq::Poly> &KeySwitchingKey::c1_polynomials()
    const {
  if (!pImpl) {
    throw ParameterException("KeySwitchingKey is not initialized");
  }
  return pImpl->c1;
}

// Serialization implementation
// Serialization implementation
yacl::Buffer KeySwitchingKey::Serialize() const {
  KeySwitchingKeyData data;
  data.ciphertext_level = pImpl->ciphertext_level;
  data.ksk_level = pImpl->ksk_level;
  data.log_base = pImpl->log_base;
  data.has_seed = pImpl->seed.has_value();
  if (data.has_seed) {
    const auto &s = pImpl->seed.value();
    data.seed.assign(s.begin(), s.end());
  }

  // Serialize parameters
  data.params.polynomial_degree = pImpl->par->degree();
  data.params.plaintext_modulus = pImpl->par->plaintext_modulus();
  data.params.moduli = pImpl->par->moduli();
  data.params.moduli_sizes = pImpl->par->moduli_sizes();
  data.params.variance = pImpl->par->variance();

  // Serialize polynomials
  data.c0_polys.reserve(pImpl->c0.size());
  for (const auto &poly : pImpl->c0) {
    data.c0_polys.push_back(poly.to_bytes());
  }

  data.c1_polys.reserve(pImpl->c1.size());
  for (const auto &poly : pImpl->c1) {
    data.c1_polys.push_back(poly.to_bytes());
  }

  return MsgpackSerializer::Serialize(data);
}

void KeySwitchingKey::Deserialize(yacl::ByteContainerView in,
                                  std::shared_ptr<BfvParameters> params) {
  *this = from_bytes(in, std::move(params));
}

KeySwitchingKey KeySwitchingKey::from_bytes(
    yacl::ByteContainerView bytes, std::shared_ptr<BfvParameters> params) {
  auto data = MsgpackSerializer::Deserialize<KeySwitchingKeyData>(bytes);

  std::optional<std::array<uint8_t, 32>> seed;
  if (data.has_seed) {
    if (data.seed.size() != 32) {
      throw SerializationException("Invalid seed size in KeySwitchingKey");
    }
    std::array<uint8_t, 32> s;
    std::copy(data.seed.begin(), data.seed.end(), s.begin());
    seed = s;
  }

  // Reconstruct components
  // KeySwitchingKey components c0/c1 are at the ksk_level
  auto ctx_ksk = params->ctx_at_level(data.ksk_level);

  std::vector<::bfv::math::rq::Poly> c0;
  c0.reserve(data.c0_polys.size());
  for (const auto &poly_bytes : data.c0_polys) {
    c0.push_back(::bfv::math::rq::Poly::from_bytes(poly_bytes, ctx_ksk));
  }

  std::vector<::bfv::math::rq::Poly> c1;
  c1.reserve(data.c1_polys.size());
  for (const auto &poly_bytes : data.c1_polys) {
    c1.push_back(::bfv::math::rq::Poly::from_bytes(poly_bytes, ctx_ksk));
  }

  return from_components(std::move(params), seed, std::move(c0), std::move(c1),
                         data.ciphertext_level, data.ksk_level, data.log_base);
}

KeySwitchingKey KeySwitchingKey::from_components(
    std::shared_ptr<BfvParameters> params,
    std::optional<std::array<uint8_t, 32>> seed,
    std::vector<::bfv::math::rq::Poly> c0_polys,
    std::vector<::bfv::math::rq::Poly> c1_polys, size_t ciphertext_level,
    size_t ksk_level, size_t log_base) {
  // Create contexts for the given levels
  auto ctx_ciphertext = params->ctx_at_level(ciphertext_level);
  auto ctx_ksk = params->ctx_at_level(ksk_level);

  // Create Impl with all components
  auto impl = std::make_unique<Impl>(
      params, seed, std::move(c0_polys), std::move(c1_polys), ciphertext_level,
      ctx_ciphertext, ksk_level, ctx_ksk, log_base);

  return KeySwitchingKey(std::move(impl));
}

}  // namespace bfv
}  // namespace crypto
