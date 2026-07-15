#include "util/bfv_param_advisor.h"

#include <algorithm>
#include <cmath>
#include <sstream>

#include "crypto/bfv_parameters.h"
#include "crypto/exceptions.h"
#include "math/modulus.h"
#include "math/primes.h"

namespace crypto::bfv {

namespace {

struct EstimationBreakdown {
  size_t inferred_mul_depth = 0;
  size_t effective_mul_depth = 0;
  size_t profile_penalty_bits = 0;
  size_t logq_required = 0;
};

bool HasOpProfile(const OpProfile &profile) {
  return profile.num_mul > 0 || profile.num_relin > 0 || profile.num_rot > 0;
}

size_t CeilLog2(size_t value) {
  if (value <= 1) {
    return 0;
  }

  size_t power = 0;
  size_t threshold = 1;
  while (threshold < value) {
    threshold <<= 1;
    ++power;
  }
  return power;
}

// Module B: Security Guardrail
size_t MaxLogQAllowed128(size_t degree) {
  switch (degree) {
    case 4096:
      return 109;
    case 8192:
      return 218;
    case 16384:
      return 438;
    default:
      return 0;  // 1024/2048 or other not supported
  }
}

// Module C: LogQ Estimator
EstimationBreakdown EstimateLogQRequired(size_t pt_bits, size_t mul_depth,
                                         const OpProfile &profile,
                                         OptimizationStrategy strategy) {
  // Base noise budget for BFV
  double noise_bits = pt_bits + 10;

  // Strategy margins
  double margin = 20;  // Default kBalanced
  if (strategy == OptimizationStrategy::kFast)
    margin = 10;
  else if (strategy == OptimizationStrategy::kSafe)
    margin = 30;

  EstimationBreakdown breakdown;
  if (HasOpProfile(profile) && profile.num_mul > 0) {
    // A circuit with k ciphertext-ciphertext multiplications has at least
    // ceil(log2(k + 1)) depth in a balanced tree. This is a conservative lower
    // bound when explicit depth is omitted.
    breakdown.inferred_mul_depth = CeilLog2(profile.num_mul + 1);
  }
  breakdown.effective_mul_depth =
      std::max(mul_depth, breakdown.inferred_mul_depth);

  // Depth remains the primary correctness signal. We estimate ~35 bits per
  // multiplicative level for BFV correctness.
  noise_bits += breakdown.effective_mul_depth * 35;

  if (HasOpProfile(profile)) {
    const size_t extra_muls =
        profile.num_mul > breakdown.effective_mul_depth
            ? profile.num_mul - breakdown.effective_mul_depth
            : 0;

    // Profile penalties are sublinear on total operation volume so that they
    // refine, rather than dominate, the path-depth estimate.
    const double mul_volume_penalty = 4.0 * std::log2(1.0 + extra_muls);
    const double relin_penalty = 2.0 * std::log2(1.0 + profile.num_relin);
    const double rotation_penalty = 1.0 * std::log2(1.0 + profile.num_rot);
    breakdown.profile_penalty_bits = static_cast<size_t>(
        std::ceil(mul_volume_penalty + relin_penalty + rotation_penalty));
    noise_bits += breakdown.profile_penalty_bits;
  }

  breakdown.logq_required = static_cast<size_t>(std::ceil(noise_bits + margin));
  return breakdown;
}

// Module D: Degree Selector
size_t ChooseDegree128(size_t logq_required) {
  const std::vector<size_t> candidates = {4096, 8192, 16384};

  for (size_t deg : candidates) {
    size_t max_logq = MaxLogQAllowed128(deg);
    if (logq_required <= max_logq) {
      return deg;
    }
  }

  // If we reach here, no degree satisfied the requirement
  size_t max_supported = MaxLogQAllowed128(16384);
  std::stringstream ss;
  ss << "Required logq (" << logq_required << ") exceeds maximum supported ("
     << max_supported << ") for 128-bit security. "
     << "Try reducing limit or plaintext size.";
  throw ParameterException(ss.str());
}

// Module E: Moduli Sizes Generator
// Ensures all moduli are at least MIN_MODULUS_BITS (40) for RNS stability.
std::vector<size_t> MakeModuliSizes(size_t logq_target) {
  constexpr size_t MAX_MODULUS_BITS = 60;
  constexpr size_t MIN_MODULUS_BITS = 40;

  std::vector<size_t> sizes;

  // Calculate how many full 60-bit moduli we can use
  size_t num_full = logq_target / MAX_MODULUS_BITS;
  size_t remainder = logq_target % MAX_MODULUS_BITS;

  // If remainder is 0, we're done with all 60-bit moduli
  if (remainder == 0) {
    sizes.assign(num_full, MAX_MODULUS_BITS);
    return sizes;
  }

  // If remainder >= MIN_MODULUS_BITS, just add it as a final modulus
  if (remainder >= MIN_MODULUS_BITS) {
    sizes.assign(num_full, MAX_MODULUS_BITS);
    sizes.push_back(remainder);
    return sizes;
  }

  // remainder < MIN_MODULUS_BITS (e.g., remainder = 1..39)
  // We need to redistribute to avoid small moduli

  if (num_full == 0) {
    // Edge case: logq_target < 40 (very small, unlikely)
    // Just use the target directly (will fail validation later if < 10)
    sizes.push_back(logq_target);
    return sizes;
  }

  // Strategy: Borrow from full moduli and redistribute evenly
  // Total bits to distribute = num_full * 60 + remainder
  // We want each modulus to be >= MIN_MODULUS_BITS and <= MAX_MODULUS_BITS

  // Option 1: Use (num_full) moduli, averaging bits
  // Average = (num_full * 60 + remainder) / num_full
  // This might exceed 60 or be unbalanced

  // Option 2: Use (num_full + 1) moduli, distributed evenly
  size_t total_bits = num_full * MAX_MODULUS_BITS + remainder;
  size_t num_moduli = num_full + 1;
  size_t base_size = total_bits / num_moduli;
  size_t extra = total_bits % num_moduli;

  // Check if base_size is valid
  if (base_size >= MIN_MODULUS_BITS && base_size <= MAX_MODULUS_BITS) {
    // Distribute: some moduli get base_size+1, others get base_size
    for (size_t i = 0; i < num_moduli; ++i) {
      if (i < extra) {
        sizes.push_back(base_size + 1);
      } else {
        sizes.push_back(base_size);
      }
    }
  } else if (base_size < MIN_MODULUS_BITS) {
    // Too few bits per modulus, reduce num_moduli
    // This means we need to use fewer, larger moduli
    // Use num_full moduli but accept some > 60? No, max is 60.
    // Just use num_full moduli, each getting (total_bits / num_full)
    // which might exceed 60. We accept up to 62 in practice.
    num_moduli = num_full;
    base_size = total_bits / num_moduli;
    extra = total_bits % num_moduli;
    for (size_t i = 0; i < num_moduli; ++i) {
      sizes.push_back(base_size + (i < extra ? 1 : 0));
    }
  } else {
    // base_size > MAX_MODULUS_BITS, need more moduli
    // Increase num_moduli until base_size <= MAX_MODULUS_BITS
    while (base_size > MAX_MODULUS_BITS &&
           num_moduli < total_bits / MIN_MODULUS_BITS + 1) {
      num_moduli++;
      base_size = total_bits / num_moduli;
      extra = total_bits % num_moduli;
    }
    for (size_t i = 0; i < num_moduli; ++i) {
      sizes.push_back(base_size + (i < extra ? 1 : 0));
    }
  }

  return sizes;
}

// Bit length utility
size_t BitLength(uint64_t n) {
  if (n == 0) return 0;
  return 64 - __builtin_clzll(n);
}

}  // namespace

std::string ParamAdvisorReport::ToJson() const {
  std::stringstream ss;
  ss << "{";
  ss << "\"chosen_degree\": " << chosen_degree << ", ";
  ss << "\"pt_bits\": " << pt_bits << ", ";
  ss << "\"inferred_mul_depth\": " << inferred_mul_depth << ", ";
  ss << "\"effective_mul_depth\": " << effective_mul_depth << ", ";
  ss << "\"profile_penalty_bits\": " << profile_penalty_bits << ", ";
  ss << "\"logq_required\": " << logq_required << ", ";
  ss << "\"logq_max_allowed\": " << logq_max_allowed << ", ";
  ss << "\"logq_actual\": " << logq_actual << ", ";
  ss << "\"moduli_sizes\": [";
  for (size_t i = 0; i < moduli_sizes.size(); ++i) {
    ss << moduli_sizes[i] << (i < moduli_sizes.size() - 1 ? ", " : "");
  }
  ss << "], ";
  ss << "\"estimated_ciphertext_bytes\": " << estimated_ciphertext_bytes
     << ", ";
  ss << "\"estimated_relin_key_bytes\": " << estimated_relin_key_bytes << ", ";
  ss << "\"warnings\": [";
  for (size_t i = 0; i < warnings.size(); ++i) {
    ss << "\"" << warnings[i] << "\"" << (i < warnings.size() - 1 ? ", " : "");
  }
  ss << "]";
  ss << "}";
  return ss.str();
}

ParamAdvisorResult BfvParamAdvisor::Recommend(const ParamAdvisorRequest &req) {
  // 1. Validate Input
  if ((req.plaintext_modulus == 0 && req.plaintext_nbits == 0) ||
      (req.plaintext_modulus != 0 && req.plaintext_nbits != 0)) {
    throw ParameterException(
        "Invalid request: Must provide exactly one of plaintext_modulus or "
        "plaintext_nbits.");
  }

  ParamAdvisorResult result;
  ParamAdvisorReport &report = result.report;

  // 2. Determine pt_bits and estimate logq
  if (req.plaintext_modulus != 0) {
    report.pt_bits = BitLength(req.plaintext_modulus);
  } else {
    report.pt_bits = req.plaintext_nbits;
  }

  const auto breakdown = EstimateLogQRequired(report.pt_bits, req.mul_depth,
                                              req.op_profile, req.strategy);
  report.inferred_mul_depth = breakdown.inferred_mul_depth;
  report.effective_mul_depth = breakdown.effective_mul_depth;
  report.profile_penalty_bits = breakdown.profile_penalty_bits;
  report.logq_required = breakdown.logq_required;

  if (HasOpProfile(req.op_profile) && req.mul_depth == 0 &&
      report.inferred_mul_depth > 0) {
    report.warnings.push_back(
        "mul_depth was not provided; inferred effective depth " +
        std::to_string(report.inferred_mul_depth) +
        " from num_mul=" + std::to_string(req.op_profile.num_mul) +
        " using a balanced-tree heuristic.");
  }
  if (HasOpProfile(req.op_profile) && req.mul_depth > 0 &&
      report.inferred_mul_depth > req.mul_depth) {
    report.warnings.push_back(
        "The profile implies a deeper multiplication path than mul_depth; "
        "using effective depth " +
        std::to_string(report.effective_mul_depth) + ".");
  }
  if (req.op_profile.num_mul == 0 && req.op_profile.num_relin > 0) {
    report.warnings.push_back(
        "num_relin is non-zero while num_mul is zero; treating the profile as "
        "rotation/relinearization overhead without additional multiplicative "
        "depth.");
  }
  if (req.op_profile.num_relin > req.op_profile.num_mul &&
      req.op_profile.num_mul > 0) {
    report.warnings.push_back(
        "num_relin exceeds num_mul; ensure the profile counts relinearization "
        "events consistently.");
  }

  // 3. Choose Degree
  report.chosen_degree = ChooseDegree128(report.logq_required);
  report.logq_max_allowed = MaxLogQAllowed128(report.chosen_degree);

  // 4. Determine logq_target
  size_t logq_target = report.logq_required;
  // Using required is robust as long as it's <= max (checked by ChooseDegree)

  // 5. Generate Moduli Sizes
  report.moduli_sizes = MakeModuliSizes(logq_target);

  // Verify logq_actual
  report.logq_actual = 0;
  for (auto s : report.moduli_sizes) report.logq_actual += s;

  // 6. Plaintext Modulus Generation and Validation
  uint64_t final_p = req.plaintext_modulus;
  uint64_t two_n = 2 * report.chosen_degree;

  if (final_p == 0) {
    // Generate prime
    uint64_t upper = (1ULL << req.plaintext_nbits) - 1;
    if (req.plaintext_nbits >= 64) upper = UINT64_MAX;

    auto p_opt =
        ::bfv::math::zq::generate_prime(req.plaintext_nbits, two_n, upper);
    if (!p_opt.has_value()) {
      throw ParameterException("Failed to generate plaintext modulus prime.");
    }
    final_p = *p_opt;
  } else {
    // Validate user provided p
    if (final_p % two_n != 1) {
      throw ParameterException(
          "Plaintext modulus " + std::to_string(final_p) +
          " is not valid for degree " + std::to_string(report.chosen_degree) +
          " (must be 1 mod " + std::to_string(two_n) + " for NTT).");
    }
  }

  // Verify Modulus New
  if (!::bfv::math::zq::Modulus::New(final_p)) {
    throw ParameterException(
        "Plaintext modulus is invalid (Modulus::New failed).");
  }

  // 7. Memory Estimation
  // Ciphertext: 2 polynomials * degree * size_of_coeff * num_moduli
  // num_moduli = moduli_sizes.size() + 1 (for extended basis in BFV keygen? No,
  // just fresh ciphertext) Ciphertext fresh: 2 polys. Each poly has 'level+1'
  // RNS components. Fresh ciphertext is at max level.
  size_t num_rns = report.moduli_sizes.size();
  report.estimated_ciphertext_bytes = 2 * report.chosen_degree * 8 * num_rns;

  // RelinKey: roughly decompostion * inputs.
  // Simple check: assume K=1 or max level decomposition?
  // Generally heavy. Let's estimate for full decomposition.
  // RelinKey has (L) parts? Depending on implementation.
  // Let's assume size is roughly num_moduli * ciphertext_size for simplicity of
  // MVP.
  report.estimated_relin_key_bytes =
      num_rns * report.estimated_ciphertext_bytes;

  // 8. Build Parameters
  result.params = BfvParametersBuilder()
                      .set_degree(report.chosen_degree)
                      .set_plaintext_modulus(final_p)
                      .set_moduli_sizes(report.moduli_sizes)
                      .set_variance(req.variance)
                      .build_arc();

  // 9. Fill Report Summary
  std::stringstream ss;
  ss << "BfvParameters Recommendation (128-bit Security, ";
  switch (req.strategy) {
    case OptimizationStrategy::kFast:
      ss << "Fast";
      break;
    case OptimizationStrategy::kBalanced:
      ss << "Balanced";
      break;
    case OptimizationStrategy::kSafe:
      ss << "Safe";
      break;
  }
  ss << "):\n";
  ss << "  - Degree: " << report.chosen_degree << "\n";
  ss << "  - Plaintext Modulus: " << final_p << " (" << report.pt_bits
     << " bits)\n";
  ss << "  - Requested Multiplicative Depth: " << req.mul_depth << "\n";
  ss << "  - Effective Multiplicative Depth: " << report.effective_mul_depth;
  if (report.inferred_mul_depth > 0) {
    ss << " (profile inferred " << report.inferred_mul_depth << ")";
  }
  ss << "\n";
  ss << "  - Profile Penalty Bits: " << report.profile_penalty_bits << "\n";
  ss << "  - LogQ Required: " << report.logq_required << "\n";
  ss << "  - LogQ Actual: " << report.logq_actual
     << " (limit: " << report.logq_max_allowed << ")\n";
  ss << "  - Moduli Sizes: [";
  for (size_t i = 0; i < report.moduli_sizes.size(); ++i) {
    ss << report.moduli_sizes[i]
       << (i < report.moduli_sizes.size() - 1 ? ", " : "");
  }
  ss << "]\n";
  ss << "  - Est. Ciphertext Size: "
     << report.estimated_ciphertext_bytes / 1024.0 << " KB\n";
  if (!report.warnings.empty()) {
    ss << "  - Warnings:\n";
    for (const auto &warning : report.warnings) {
      ss << "    * " << warning << "\n";
    }
  }

  report.summary = ss.str();

  return result;
}

}  // namespace crypto::bfv
