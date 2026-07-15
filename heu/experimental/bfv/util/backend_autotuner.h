#pragma once

#include <cstddef>
#include <memory>
#include <string>

#include "crypto/bfv_parameters.h"
#include "crypto/keyset_planner.h"

namespace crypto::bfv {

struct BackendAutotuningRequest {
  std::shared_ptr<BfvParameters> params;
  WorkloadProfile workload;
  size_t estimated_batch_ciphertext_count = 1;
};

struct BackendAutotuningDecision {
  std::string compiled_backend;
  std::string recommended_backend;
  std::string reason;
  double estimated_latency_score = 0.0;
};

class BackendAutotuner {
 public:
  static BackendAutotuningDecision Recommend(
      const BackendAutotuningRequest &request);
};

}  // namespace crypto::bfv
