#pragma once

#include <string>
#include <vector>

#include "crypto/keyset_planner.h"
#include "util/bfv_param_advisor.h"

namespace crypto::bfv {

struct BfvDeploymentRequest {
  SecurityLevel security = SecurityLevel::k128;
  OptimizationStrategy strategy = OptimizationStrategy::kBalanced;

  // Provide exactly one of plaintext_modulus or plaintext_nbits.
  uint64_t plaintext_modulus = 0;
  size_t plaintext_nbits = 0;

  size_t mul_depth = 0;
  size_t variance = 10;

  WorkloadProfile workload;
};

struct BfvDeploymentPlan {
  ParamAdvisorResult parameter_plan;
  KeysetPlan keyset_plan;

  std::string compiled_mul_backend;
  std::string recommended_mul_backend;
  std::string backend_reason;

  size_t estimated_peak_ciphertext_bytes = 0;
  size_t estimated_batch_ciphertext_count = 1;
  size_t estimated_total_key_material_bytes = 0;
  size_t estimated_peak_working_set_bytes = 0;
  double estimated_latency_score = 0.0;

  std::vector<std::string> warnings;

  std::string Summary() const;
  std::string ToJson() const;
};

class BfvDeploymentPlanner {
 public:
  static BfvDeploymentPlan Plan(const BfvDeploymentRequest &request);
};

}  // namespace crypto::bfv
