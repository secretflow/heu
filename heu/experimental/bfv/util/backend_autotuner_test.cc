#include "util/backend_autotuner.h"

#include <gtest/gtest.h>

#include "util/bfv_param_advisor.h"

namespace crypto::bfv {

namespace {

std::shared_ptr<BfvParameters> RecommendParams(size_t plaintext_nbits,
                                               size_t mul_depth) {
  ParamAdvisorRequest request;
  request.plaintext_nbits = plaintext_nbits;
  request.mul_depth = mul_depth;
  return BfvParamAdvisor::Recommend(request).params;
}

}  // namespace

TEST(BackendAutotunerTest, PrefersResidueTransferForSmallWorkloads) {
  BackendAutotuningRequest request;
  request.params = RecommendParams(20, 1);
  request.workload.batch_size = 16;
  request.workload.ciphertext_fan_out = 1;
  request.workload.num_ciphertext_multiplications = 1;
  request.estimated_batch_ciphertext_count = 1;

  auto decision = BackendAutotuner::Recommend(request);

  EXPECT_FALSE(decision.compiled_backend.empty());
  EXPECT_EQ(decision.recommended_backend, "residue_transfer_candidate");
  EXPECT_NE(decision.reason.find("degree="), std::string::npos);
  EXPECT_GT(decision.estimated_latency_score, 0.0);
}

TEST(BackendAutotunerTest, PrefersAuxBaseForWideBatchyWorkloads) {
  BackendAutotuningRequest request;
  request.params = RecommendParams(20, 2);
  request.workload.batch_size = 512;
  request.workload.ciphertext_fan_out = 4;
  request.workload.num_ciphertext_multiplications = 2;
  request.workload.num_inner_sum_ops = 3;
  request.workload.column_rotation_histogram = {
      RotationUse{1, 12},
      RotationUse{3, 5},
  };
  request.estimated_batch_ciphertext_count = 2;

  auto decision = BackendAutotuner::Recommend(request);

  EXPECT_EQ(decision.recommended_backend, "aux_base_candidate");
  EXPECT_NE(decision.reason.find("batch_size=512"), std::string::npos);
  EXPECT_GT(decision.estimated_latency_score, 1.0);
}

}  // namespace crypto::bfv
