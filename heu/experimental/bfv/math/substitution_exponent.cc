#include "math/substitution_exponent.h"

#include "math/exceptions.h"

namespace bfv::math::rq {

/**
 * @brief PIMPL implementation class for SubstitutionExponent.
 */
class SubstitutionExponent::Impl {
 public:
  size_t exponent;
  std::shared_ptr<const Context> ctx;
  std::vector<size_t> power_bitrev;
  std::vector<bool> power_bitrev_sign;

  Impl() = default;
  ~Impl() = default;

  // Disable copy
  Impl(const Impl &) = delete;
  Impl &operator=(const Impl &) = delete;

  // Enable move
  Impl(Impl &&) = default;
  Impl &operator=(Impl &&) = default;
};

SubstitutionExponent::SubstitutionExponent(std::shared_ptr<Impl> impl)
    : pimpl_(std::move(impl)) {}

SubstitutionExponent::~SubstitutionExponent() = default;

SubstitutionExponent::SubstitutionExponent(SubstitutionExponent &&) noexcept =
    default;
SubstitutionExponent &SubstitutionExponent::operator=(
    SubstitutionExponent &&) noexcept = default;

std::shared_ptr<SubstitutionExponent> SubstitutionExponent::create(
    std::shared_ptr<const Context> ctx, size_t original_exponent) {
  size_t degree = ctx->degree();
  size_t two_degree = 2 * degree;

  // Reduce exponent modulo 2*degree first
  size_t exponent = original_exponent % two_degree;

  // Check if the reduced exponent is odd
  if (exponent % 2 == 0) {
    throw DefaultException("The exponent should be odd");
  }

  // Check if exponent is coprime to 2*degree using GCD
  size_t gcd_val = exponent;
  size_t temp_two_degree = two_degree;
  while (temp_two_degree != 0) {
    size_t temp = temp_two_degree;
    temp_two_degree = gcd_val % temp_two_degree;
    gcd_val = temp;
  }
  if (gcd_val != 1) {
    throw DefaultException("The exponent should be coprime to 2 * degree");
  }

  auto impl = std::make_unique<Impl>();
  impl->exponent = exponent;
  impl->ctx = ctx;

  // Compute power_bitrev for NTT automorphism:
  // For ring Z[X]/(X^N+1), NTT values are f(ζ^{2*bitrev(i)+1})
  // After σ_k: f(X^k) which maps value at ζ^p to value at ζ^{kp}
  // This is purely a permutation of the NTT slots.

  impl->power_bitrev.resize(degree);
  size_t *table_ptr = impl->power_bitrev.data();

  // Precompute log2(degree) for bit reversal
  size_t log_degree = 0;
  {
    size_t temp = degree;
    while (temp > 1) {
      temp >>= 1;
      log_degree++;
    }
  }

  // Helper for n-bit reversal
  auto bit_reverse_n = [log_degree](size_t x) -> size_t {
    size_t result = 0;
    for (size_t j = 0; j < log_degree; ++j) {
      result = (result << 1) | (x & 1);
      x >>= 1;
    }
    return result;
  };

  for (size_t i = 0; i < degree; ++i) {
    size_t br_i = bit_reverse_n(i);
    size_t power_i = 2 * br_i + 1;          // Original NTT power
    size_t new_power = exponent * power_i;  // After σ_k

    // Reduce power mod 2N
    size_t reduced_power = new_power % two_degree;

    // Find j such that 2*bitrev(j)+1 = reduced_power
    size_t br_j = (reduced_power - 1) / 2;
    size_t j = bit_reverse_n(br_j);

    // Store as Gather map: table[i] = j
    // So output[i] comes from input[j]
    // i corresponds to power p
    // j corresponds to power p*k
    // A'(zeta_p) = A(zeta_{pk}) -> val at i comes from val at j
    table_ptr[i] = j;
  }

  return std::shared_ptr<SubstitutionExponent>(
      new SubstitutionExponent(std::move(impl)));
}

size_t SubstitutionExponent::exponent() const { return pimpl_->exponent; }

const std::vector<size_t> &SubstitutionExponent::power_bitrev() const {
  return pimpl_->power_bitrev;
}

const std::vector<bool> &SubstitutionExponent::power_bitrev_sign() const {
  return pimpl_->power_bitrev_sign;
}

std::shared_ptr<const Context> SubstitutionExponent::context() const {
  return pimpl_->ctx;
}

}  // namespace bfv::math::rq
