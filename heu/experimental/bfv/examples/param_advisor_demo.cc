#include <iostream>

#include "heu/experimental/bfv/crypto/ciphertext.h"
#include "heu/experimental/bfv/crypto/encoding.h"
#include "heu/experimental/bfv/crypto/plaintext.h"
#include "heu/experimental/bfv/crypto/secret_key.h"
#include "heu/experimental/bfv/util/bfv_param_advisor.h"

using namespace crypto::bfv;

int main() {
  std::cout << "=== BFV Parameter Advisor Demo ===\n" << std::endl;

  // 1. Basic Usage: Depth-based
  std::cout << "--- Scenario 1: Basic (Depth-based) ---" << std::endl;
  {
    ParamAdvisorRequest req;
    req.plaintext_nbits = 20;
    req.mul_depth = 2;  // e.g., x^4

    auto result = BfvParamAdvisor::Recommend(req);

    std::cout << "Recommended Degree: " << result.report.chosen_degree
              << std::endl;
    std::cout << "Estimated Ciphertext Size: "
              << result.report.estimated_ciphertext_bytes << " bytes"
              << std::endl;
    std::cout << "JSON Report:\n"
              << result.report.ToJson() << "\n"
              << std::endl;
  }

  // 2. Advanced Usage: Profile-based
  std::cout << "--- Scenario 2: Advanced (Profile-based) ---" << std::endl;
  {
    ParamAdvisorRequest req;
    req.plaintext_nbits = 20;
    // Use Safe strategy which provides maximum margin
    req.strategy = OptimizationStrategy::kSafe;
    req.op_profile = {.num_mul = 8, .num_relin = 4, .num_rot = 12};

    auto result = BfvParamAdvisor::Recommend(req);

    // Verify parameters
    std::string fail_reason;
    if (result.params->SelfTest(&fail_reason)) {
      std::cout << "[Check] Parameters passed self-test." << std::endl;
    } else {
      std::cout << "[Check] Parameters FAILED self-test. Reason:\n"
                << fail_reason << std::endl;
    }

    std::cout << "Effective Depth: " << result.report.effective_mul_depth
              << " (inferred: " << result.report.inferred_mul_depth << ")"
              << std::endl;
    if (!result.report.warnings.empty()) {
      std::cout << "Warnings:" << std::endl;
      for (const auto &warning : result.report.warnings) {
        std::cout << "  - " << warning << std::endl;
      }
    }
    std::cout << "JSON Report:\n" << result.report.ToJson() << std::endl;
  }

  return 0;
}
