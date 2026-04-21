#pragma once

/**
 * @file bfv_param_advisor.h
 * @brief BFV Parameter Advisor - Intelligent Parameter Selection Tool
 *
 * This module helps users select secure and efficient BFV parameters based on
 * their specific application requirements. It abstracts away the complexity of
 * manual parameter tuning (e.g., choosing polynomial degree, setting
 * coefficient moduli).
 *
 * =============================================================================
 * Usage Guide
 * =============================================================================
 *
 * 1. Basic Usage (Depth-based)
 *    If you simply know the multiplicative depth of your circuit:
 *
 *    ```cpp
 *    ParamAdvisorRequest req;
 *    req.plaintext_nbits = 20; // Size of your plaintext elements in bits
 *    req.mul_depth = 3;        // Multiplicative depth of your circuit
 *
 *    auto result = BfvParamAdvisor::Recommend(req);
 *    // Result contains both the constructed parameters and a detailed report
 *    auto params = result.params;
 *    ```
 *
 * 2. Advanced Usage (Profile-based)
 *    For more accurate estimation, provide an operation profile:
 *
 *    ```cpp
 *    ParamAdvisorRequest req;
 *    req.plaintext_nbits = 20;
 *    req.op_profile = {
 *        .num_mul = 10,    // Total number of homomorphic multiplications
 *        .num_relin = 5,   // Total number of relinearizations
 *        .num_rot = 2      // Total number of rotations
 *    };
 *    // Optional: if omitted, the advisor will infer a conservative
 *    // multiplicative depth from num_mul using a heuristic model.
 *    req.mul_depth = 4;
 *    // Optional: Choose strategy (kFast, kBalanced, kSafe)
 *    req.strategy = OptimizationStrategy::kSafe;
 *
 *    auto result = BfvParamAdvisor::Recommend(req);
 *    ```
 *
 * 3. Validation
 *    The advisor performs checks to prevent unsafe parameters.
 *    You can also run a self-test on the generated parameters:
 *
 *    ```cpp
 *    if (!result.params->SelfTest()) {
 *        // Handle error
 *    }
 *    ```
 *
 * 4. Reporting
 *    The `result.report` structure contains detailed info and JSON output.
 *    ```cpp
 *    std::cout << result.report.ToJson() << std::endl;
 *    ```
 * =============================================================================
 */

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "crypto/bfv_parameters.h"

namespace crypto::bfv {

enum class SecurityLevel { k128 };

enum class OptimizationStrategy { kFast, kBalanced, kSafe };

struct OpProfile {
  size_t num_mul = 0;
  size_t num_relin = 0;
  size_t num_rot = 0;
};

struct ParamAdvisorRequest {
  SecurityLevel security = SecurityLevel::k128;
  OptimizationStrategy strategy = OptimizationStrategy::kBalanced;

  // Provide either plaintext_modulus or plaintext_nbits
  uint64_t plaintext_modulus = 0;
  size_t plaintext_nbits = 0;

  size_t mul_depth = 0;  // Multiplication depth B (simple mode)
  OpProfile op_profile;  // Operation profile (advanced mode)

  size_t variance = 10;  // Default 10
};

struct ParamAdvisorReport {
  size_t chosen_degree = 0;
  size_t pt_bits = 0;
  size_t inferred_mul_depth = 0;
  size_t effective_mul_depth = 0;
  size_t profile_penalty_bits = 0;

  size_t logq_required = 0;     // Estimated logq required for correctness
  size_t logq_max_allowed = 0;  // Max logq allowed by security guardrail
  size_t logq_actual = 0;       // Sum of moduli_sizes

  std::vector<size_t> moduli_sizes;  // Actual bit sizes used

  // Memory estimations
  size_t estimated_ciphertext_bytes = 0;
  size_t estimated_relin_key_bytes = 0;

  std::vector<std::string> warnings;
  std::string summary;

  std::string ToJson() const;
};

struct ParamAdvisorResult {
  std::shared_ptr<BfvParameters> params;
  ParamAdvisorReport report;
};

class BfvParamAdvisor {
 public:
  static ParamAdvisorResult Recommend(const ParamAdvisorRequest &req);
};

}  // namespace crypto::bfv
