#include "crypto/operators.h"

#include <algorithm>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

#include "crypto/bfv_parameters.h"
#include "crypto/multiplicator.h"
#include "crypto/relinearization_key.h"
#include "crypto/secret_key.h"
#include "math/biguint.h"
#include "math/context.h"
#include "math/poly.h"
#include "math/primes.h"
#include "math/representation.h"
#include "math/scaling_factor.h"

namespace crypto {
namespace bfv {

namespace {

std::vector<uint64_t> BuildDefaultExtendedBasis(
    const std::shared_ptr<BfvParameters> &params, size_t level) {
  auto ctx = params->ctx_at_level(level);

  size_t total_coeff_bit_count = 0;
  auto moduli_sizes = params->moduli_sizes();
  for (size_t i = 0; i < ctx->moduli().size(); ++i) {
    total_coeff_bit_count += moduli_sizes[i];
  }

  size_t plain_modulus_bit_count = 0;
  uint64_t plain_modulus = params->plaintext_modulus();
  while (plain_modulus > 0) {
    ++plain_modulus_bit_count;
    plain_modulus >>= 1;
  }
  if (plain_modulus_bit_count == 0) {
    plain_modulus_bit_count = 1;
  }

  constexpr size_t kInternalModBitCount = 61;
  size_t base_B_size = ctx->moduli().size();
  if (32 + plain_modulus_bit_count + total_coeff_bit_count >=
      kInternalModBitCount * ctx->moduli().size() + kInternalModBitCount) {
    ++base_B_size;
  }
  const size_t base_Bsk_size = base_B_size + 1;
  const size_t base_Bsk_m_tilde_size = base_Bsk_size + 1;

  std::vector<uint64_t> sampled_primes;
  sampled_primes.reserve(base_Bsk_m_tilde_size);
  uint64_t upper_bound = 1ULL << kInternalModBitCount;
  while (sampled_primes.size() < base_Bsk_m_tilde_size) {
    auto prime_opt = ::bfv::math::zq::generate_prime(
        kInternalModBitCount, 2 * params->degree(), upper_bound);
    if (!prime_opt.has_value()) {
      throw MathException("Failed to generate prime for extended basis");
    }
    upper_bound = prime_opt.value();

    bool found = false;
    for (uint64_t existing : sampled_primes) {
      if (existing == upper_bound) {
        found = true;
        break;
      }
    }
    for (uint64_t existing : ctx->moduli()) {
      if (existing == upper_bound) {
        found = true;
        break;
      }
    }

    if (!found) {
      sampled_primes.push_back(upper_bound);
    }
  }

  std::vector<uint64_t> extended_basis;
  extended_basis.reserve(ctx->moduli().size() + base_Bsk_size);
  for (uint64_t modulus : ctx->moduli()) {
    extended_basis.push_back(modulus);
  }

  const uint64_t m_sk = sampled_primes[0];
  for (size_t i = 2; i < sampled_primes.size(); ++i) {
    extended_basis.push_back(sampled_primes[i]);
  }
  extended_basis.push_back(m_sk);

  return extended_basis;
}

}  // namespace

// Helper function to create a basic multiplicator for operators
std::unique_ptr<Multiplicator> create_basic_multiplicator(
    std::shared_ptr<BfvParameters> params, size_t level) {
  auto ctx = params->ctx_at_level(level);
  auto extended_basis = BuildDefaultExtendedBasis(params, level);

  // Create scaling factors
  auto one_factor = ::bfv::math::rns::ScalingFactor::one();
  auto post_mul_factor = ::bfv::math::rns::ScalingFactor(
      ::bfv::math::rns::BigUint(params->plaintext_modulus()),
      ::bfv::math::rns::BigUint(ctx->modulus()));

  return Multiplicator::create_leveled(one_factor, one_factor, extended_basis,
                                       post_mul_factor, level, params);
}

// Helper function to validate ciphertext compatibility
void validate_ciphertext_compatibility(const Ciphertext &lhs,
                                       const Ciphertext &rhs) {
  if (!lhs.parameters() || !rhs.parameters()) {
    throw ParameterException("Ciphertexts must have valid parameters");
  }
  if (*lhs.parameters() != *rhs.parameters()) {
    throw ParameterException("Ciphertexts must have the same parameters");
  }
  if (lhs.level() != rhs.level()) {
    throw ParameterException("Ciphertexts must be at the same level");
  }
}

// Helper function to validate ciphertext-plaintext compatibility
void validate_ciphertext_plaintext_compatibility(const Ciphertext &ct,
                                                 const Plaintext &pt) {
  if (!ct.parameters() || !pt.parameters()) {
    throw ParameterException(
        "Ciphertext and plaintext must have valid parameters");
  }
  if (*ct.parameters() != *pt.parameters()) {
    throw ParameterException(
        "Ciphertext and plaintext must have the same parameters");
  }
  if (ct.level() != pt.level()) {
    throw ParameterException(
        "Ciphertext and plaintext must be at the same level");
  }
}

// Addition: Ciphertext + Ciphertext
// Addition: Ciphertext + Ciphertext
Ciphertext operator+(const Ciphertext &lhs, const Ciphertext &rhs) {
  validate_ciphertext_compatibility(lhs, rhs);

  if (lhs.empty()) return rhs;
  if (rhs.empty()) return lhs;

  Ciphertext result = lhs;
  result.add_inplace(rhs);
  return result;
}

// Addition: Ciphertext + Plaintext
Ciphertext operator+(const Ciphertext &lhs, const Plaintext &rhs) {
  validate_ciphertext_plaintext_compatibility(lhs, rhs);

  if (lhs.empty()) {
    throw ParameterException("Cannot add plaintext to empty ciphertext");
  }

  // Create result (copy of lhs)
  auto result_polys = lhs.polynomials();

  // Add plaintext to the first polynomial (c0)
  auto rhs_poly = rhs.polynomial_for_ops();
  if (rhs_poly.representation() != result_polys[0].representation()) {
    rhs_poly.change_representation(result_polys[0].representation());
  }
  result_polys[0] = result_polys[0] + rhs_poly;

  return Ciphertext::from_polynomials_with_level(std::move(result_polys),
                                                 lhs.parameters(), lhs.level());
}

// Addition: Plaintext + Ciphertext (commutative)
Ciphertext operator+(const Plaintext &lhs, const Ciphertext &rhs) {
  return rhs + lhs;
}

// Subtraction: Ciphertext - Ciphertext
// Subtraction: Ciphertext - Ciphertext
Ciphertext operator-(const Ciphertext &lhs, const Ciphertext &rhs) {
  validate_ciphertext_compatibility(lhs, rhs);

  if (lhs.empty()) return -rhs;
  if (rhs.empty()) return lhs;

  // Optimization: Copy larger ciphertext to minimize resizing
  // Note: subtraction is not commutative, so we must be careful result = lhs;
  // result -= rhs. If we do result = -rhs; result += lhs; it is inefficient due
  // to negation.

  Ciphertext result = lhs;
  result.sub_inplace(rhs);
  return result;
}

// Subtraction: Ciphertext - Plaintext
Ciphertext operator-(const Ciphertext &lhs, const Plaintext &rhs) {
  validate_ciphertext_plaintext_compatibility(lhs, rhs);

  if (lhs.empty()) {
    throw ParameterException("Cannot subtract plaintext from empty ciphertext");
  }

  // Create result (copy of lhs)
  auto result_polys = lhs.polynomials();

  // Subtract plaintext from the first polynomial (c0)
  auto rhs_poly = rhs.polynomial_for_ops();
  if (rhs_poly.representation() != result_polys[0].representation()) {
    rhs_poly.change_representation(result_polys[0].representation());
  }
  result_polys[0] = result_polys[0] - rhs_poly;

  return Ciphertext::from_polynomials_with_level(std::move(result_polys),
                                                 lhs.parameters(), lhs.level());
}

// Subtraction: Plaintext - Ciphertext
Ciphertext operator-(const Plaintext &lhs, const Ciphertext &rhs) {
  return -(rhs - lhs);
}

static std::mutex cache_mutex;
static std::unordered_map<size_t, std::unique_ptr<Multiplicator>> *cache_ptr =
    nullptr;

// Cached multiplicator to avoid repeated construction overhead
static Multiplicator *get_cached_multiplicator(
    const std::shared_ptr<BfvParameters> &params, size_t level) {
  const size_t key = (reinterpret_cast<size_t>(params.get()) ^
                      (level * 0x9e3779b97f4a7c15ULL));
  std::lock_guard<std::mutex> lock(cache_mutex);
  if (!cache_ptr) {
    cache_ptr =
        new std::unordered_map<size_t, std::unique_ptr<Multiplicator>>();
  }

  auto it = cache_ptr->find(key);
  if (it != cache_ptr->end()) {
    return it->second.get();
  }
  auto mult = create_basic_multiplicator(params, level);
  auto *raw_ptr = mult.get();
  cache_ptr->emplace(key, std::move(mult));
  return raw_ptr;
}

// Multiplication: Ciphertext * Ciphertext
Ciphertext operator*(const Ciphertext &lhs, const Ciphertext &rhs) {
  validate_ciphertext_compatibility(lhs, rhs);

  // Output should be zero if input is zero
  if (lhs.empty() || rhs.empty()) {
    return Ciphertext::zero(lhs.parameters());
  }

  // Use cached multiplicator to avoid repeated heavy construction
  auto *multiplicator = get_cached_multiplicator(lhs.parameters(), lhs.level());

  // Handle self-multiplication (aliasing) by copying rhs
  if (&lhs == &rhs) {
    Ciphertext rhs_copy = rhs;
    return multiplicator->multiply(lhs, rhs_copy);
  }

  return multiplicator->multiply(lhs, rhs);
}

// Multiplication: Ciphertext * Plaintext
Ciphertext operator*(const Ciphertext &lhs, const Plaintext &rhs) {
  validate_ciphertext_plaintext_compatibility(lhs, rhs);

  if (lhs.empty()) {
    return lhs;
  }

  // Create result (copy of lhs polynomials)
  auto result_polys = lhs.polynomials();
  const auto target_repr = result_polys[0].representation();
  const auto &rhs_ntt = rhs.polynomial_ntt();

  // Multiply each polynomial by the plaintext
  for (auto &poly : result_polys) {
    if (poly.representation() != ::bfv::math::rq::Representation::Ntt) {
      poly.change_representation(::bfv::math::rq::Representation::Ntt);
    }
    poly = poly * rhs_ntt;
    if (target_repr != ::bfv::math::rq::Representation::Ntt) {
      poly.change_representation(target_repr);
    }
  }

  return Ciphertext::from_polynomials_with_level(std::move(result_polys),
                                                 lhs.parameters(), lhs.level());
}

// Multiplication: Plaintext * Ciphertext (commutative)
Ciphertext operator*(const Plaintext &lhs, const Ciphertext &rhs) {
  return rhs * lhs;
}

// Negation: -Ciphertext
Ciphertext operator-(const Ciphertext &operand) {
  if (operand.empty()) {
    return operand;
  }

  // Create result with negated polynomials
  std::vector<::bfv::math::rq::Poly> result_polys;
  result_polys.reserve(operand.size());

  for (size_t i = 0; i < operand.size(); ++i) {
    result_polys.push_back(-operand.polynomial(i));
  }

  return Ciphertext::from_polynomials_with_level(
      std::move(result_polys), operand.parameters(), operand.level());
}

// Assignment operators
Ciphertext &operator+=(Ciphertext &lhs, const Ciphertext &rhs) {
  lhs.add_inplace(rhs);
  return lhs;
}

Ciphertext &operator+=(Ciphertext &lhs, const Plaintext &rhs) {
  lhs = lhs + rhs;
  return lhs;
}

Ciphertext &operator-=(Ciphertext &lhs, const Ciphertext &rhs) {
  lhs.sub_inplace(rhs);
  return lhs;
}

Ciphertext &operator-=(Ciphertext &lhs, const Plaintext &rhs) {
  lhs = lhs - rhs;
  return lhs;
}

Ciphertext &operator*=(Ciphertext &lhs, const Ciphertext &rhs) {
  lhs = lhs * rhs;
  return lhs;
}

Ciphertext &operator*=(Ciphertext &lhs, const Plaintext &rhs) {
  lhs = lhs * rhs;
  return lhs;
}

void clear_operator_cache() {
  std::lock_guard<std::mutex> lock(cache_mutex);
  if (cache_ptr) {
    cache_ptr->clear();
  }
}

}  // namespace bfv
}  // namespace crypto
