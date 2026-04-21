#include "util/bfv_deployment_planner.h"

#include <gtest/gtest.h>

#include <memory>
#include <random>
#include <vector>

#include "crypto/secret_key.h"

namespace crypto::bfv {

class BfvDeploymentPlannerTest : public ::testing::Test {
 protected:
  void SetUp() override { rng_.seed(42); }

  std::mt19937_64 rng_;
};

TEST_F(BfvDeploymentPlannerTest, ProducesDeploymentPlanFromWorkload) {
  BfvDeploymentRequest request;
  request.plaintext_nbits = 20;
  request.mul_depth = 2;
  request.strategy = OptimizationStrategy::kBalanced;
  request.workload.num_ciphertext_multiplications = 2;
  request.workload.num_inner_sum_ops = 1;
  request.workload.max_expansion_level = 1;
  request.workload.batch_size = 256;
  request.workload.ciphertext_fan_out = 4;
  request.workload.column_rotation_histogram = {
      RotationUse{1, 12},
      RotationUse{3, 5},
      RotationUse{1, 2},
  };

  auto plan = BfvDeploymentPlanner::Plan(request);

  ASSERT_NE(plan.parameter_plan.params, nullptr);
  EXPECT_EQ(plan.keyset_plan.params, plan.parameter_plan.params);
  EXPECT_TRUE(plan.keyset_plan.needs_relinearization);
  EXPECT_TRUE(plan.keyset_plan.needs_inner_sum);
  EXPECT_EQ(plan.keyset_plan.profiled_batch_size, 256u);
  EXPECT_EQ(plan.keyset_plan.profiled_ciphertext_fan_out, 4u);
  ASSERT_GE(plan.keyset_plan.ranked_column_rotations.size(), 2u);
  EXPECT_EQ(plan.keyset_plan.ranked_column_rotations[0].steps, 1u);
  EXPECT_EQ(plan.keyset_plan.ranked_column_rotations[0].count, 14u);
  EXPECT_GT(plan.estimated_peak_ciphertext_bytes, 0u);
  EXPECT_GT(plan.estimated_total_key_material_bytes, 0u);
  EXPECT_GT(plan.estimated_peak_working_set_bytes,
            plan.estimated_peak_ciphertext_bytes);
  EXPECT_GT(plan.estimated_latency_score, 0.0);
  EXPECT_FALSE(plan.recommended_mul_backend.empty());
  EXPECT_FALSE(plan.compiled_mul_backend.empty());
  EXPECT_NE(plan.backend_reason.find("degree="), std::string::npos);
  EXPECT_NE(plan.Summary().find("backend="), std::string::npos);
}

TEST_F(BfvDeploymentPlannerTest, DeploymentPlanCanMaterializeSuggestedKeys) {
  BfvDeploymentRequest request;
  request.plaintext_nbits = 20;
  request.mul_depth = 1;
  request.workload.num_ciphertext_multiplications = 1;
  request.workload.column_rotation_histogram = {
      RotationUse{1, 3},
  };

  auto plan = BfvDeploymentPlanner::Plan(request);
  auto sk = SecretKey::random(plan.parameter_plan.params, rng_);

  auto ek = KeysetPlanner::BuildEvaluationKey(sk, plan.keyset_plan, rng_);
  auto maybe_rk =
      KeysetPlanner::BuildRelinearizationKey(sk, plan.keyset_plan, rng_);

  EXPECT_TRUE(ek.supports_column_rotation_by(1));
  ASSERT_TRUE(maybe_rk.has_value());
  EXPECT_FALSE(maybe_rk->empty());
}

TEST_F(BfvDeploymentPlannerTest, RotationProfileMatchesAggregateCount) {
  BfvDeploymentRequest request;
  request.plaintext_nbits = 20;
  request.mul_depth = 1;
  request.workload.column_rotation_histogram = {
      RotationUse{7, 1},
      RotationUse{3, 9},
      RotationUse{7, 4},
  };

  auto plan = BfvDeploymentPlanner::Plan(request);

  ASSERT_GE(plan.keyset_plan.ranked_column_rotations.size(), 2u);
  EXPECT_EQ(plan.keyset_plan.ranked_column_rotations[0].steps, 3u);
  EXPECT_EQ(plan.keyset_plan.ranked_column_rotations[0].count, 9u);
  EXPECT_EQ(plan.keyset_plan.ranked_column_rotations[1].steps, 7u);
  EXPECT_EQ(plan.keyset_plan.ranked_column_rotations[1].count, 5u);
  EXPECT_EQ(plan.keyset_plan.profiled_rotation_uses, 14u);
}

TEST_F(BfvDeploymentPlannerTest, DeploymentPlanExportsStructuredJson) {
  BfvDeploymentRequest request;
  request.plaintext_nbits = 20;
  request.mul_depth = 2;
  request.workload.num_ciphertext_multiplications = 2;
  request.workload.num_inner_sum_ops = 1;
  request.workload.batch_size = 256;
  request.workload.ciphertext_fan_out = 4;
  request.workload.column_rotation_histogram = {
      RotationUse{1, 6},
      RotationUse{5, 2},
  };

  auto plan = BfvDeploymentPlanner::Plan(request);
  auto json = plan.ToJson();

  EXPECT_NE(json.find("\"parameters\""), std::string::npos);
  EXPECT_NE(json.find("\"keyset\""), std::string::npos);
  EXPECT_NE(json.find("\"compiled_mul_backend\""), std::string::npos);
  EXPECT_NE(json.find("\"recommended_mul_backend\""), std::string::npos);
  EXPECT_NE(json.find("\"ranked_column_rotations\""), std::string::npos);
  EXPECT_NE(json.find("\"estimated_peak_working_set_bytes\""),
            std::string::npos);
  EXPECT_NE(json.find("\"warnings\""), std::string::npos);
}

}  // namespace crypto::bfv
