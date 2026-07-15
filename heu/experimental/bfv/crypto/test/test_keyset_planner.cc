#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <random>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/evaluation_key.h"
#include "crypto/keyset_planner.h"
#include "crypto/secret_key.h"

namespace crypto {
namespace bfv {

class KeysetPlannerTest : public ::testing::Test {
 protected:
  void SetUp() override { rng_.seed(42); }

  std::shared_ptr<BfvParameters> MakeParams() {
    return BfvParameters::default_arc(6, 16);
  }

  std::mt19937_64 rng_;
};

TEST_F(KeysetPlannerTest, PlansMinimalKeysetFromRequest) {
  auto params = MakeParams();

  KeysetRequest request;
  request.params = params;
  request.num_ciphertext_multiplications = 2;
  request.require_inner_sum = true;
  request.require_row_rotation = true;
  request.max_expansion_level = 2;
  request.column_rotations = {1, 3, 1, 4};

  auto plan = KeysetPlanner::Plan(request);

  EXPECT_TRUE(plan.needs_relinearization);
  EXPECT_TRUE(plan.needs_row_rotation);
  EXPECT_TRUE(plan.needs_inner_sum);
  EXPECT_EQ(plan.requested_column_rotations, (std::vector<size_t>{1, 3, 4}));
  EXPECT_EQ(plan.implied_column_rotations, (std::vector<size_t>{1, 2, 4}));
  EXPECT_EQ(plan.effective_column_rotations, (std::vector<size_t>{1, 2, 3, 4}));
  EXPECT_EQ(plan.estimated_galois_key_count,
            plan.effective_galois_elements.size());
  EXPECT_EQ(plan.estimated_galois_key_count, 5u);
  EXPECT_GT(plan.estimated_galois_key_bytes, 0u);
  EXPECT_GT(plan.estimated_relinearization_key_bytes, 0u);
  EXPECT_GT(plan.estimated_total_key_bytes, plan.estimated_galois_key_bytes);
  EXPECT_NE(plan.Summary().find("galois_keys=5"), std::string::npos);
}

TEST_F(KeysetPlannerTest, BuildsEvaluationKeyFromPlan) {
  auto params = MakeParams();
  auto sk = SecretKey::random(params, rng_);

  KeysetRequest request;
  request.params = params;
  request.column_rotations = {3};
  request.max_expansion_level = 2;

  auto plan = KeysetPlanner::Plan(request);
  auto ek = KeysetPlanner::BuildEvaluationKey(sk, plan, rng_);

  EXPECT_TRUE(ek.supports_column_rotation_by(3));
  EXPECT_FALSE(ek.supports_column_rotation_by(1));
  EXPECT_FALSE(ek.supports_row_rotation());
  EXPECT_FALSE(ek.supports_inner_sum());
  EXPECT_TRUE(ek.supports_expansion(2));
  EXPECT_FALSE(ek.supports_expansion(3));
}

TEST_F(KeysetPlannerTest, BuildsRelinearizationKeyOnlyWhenNeeded) {
  auto params = MakeParams();
  auto sk = SecretKey::random(params, rng_);

  KeysetRequest no_relin_request;
  no_relin_request.params = params;
  auto no_relin_plan = KeysetPlanner::Plan(no_relin_request);
  auto maybe_none =
      KeysetPlanner::BuildRelinearizationKey(sk, no_relin_plan, rng_);
  EXPECT_FALSE(maybe_none.has_value());

  KeysetRequest relin_request;
  relin_request.params = params;
  relin_request.num_ciphertext_multiplications = 1;
  auto relin_plan = KeysetPlanner::Plan(relin_request);
  auto maybe_rk = KeysetPlanner::BuildRelinearizationKey(sk, relin_plan, rng_);
  ASSERT_TRUE(maybe_rk.has_value());
  EXPECT_FALSE(maybe_rk->empty());
  EXPECT_EQ(maybe_rk->ciphertext_level(), 0u);
  EXPECT_EQ(maybe_rk->key_level(), 0u);
}

TEST_F(KeysetPlannerTest, RejectsInvalidRequests) {
  auto params = MakeParams();

  KeysetRequest invalid_rotation_zero;
  invalid_rotation_zero.params = params;
  invalid_rotation_zero.column_rotations = {0};
  EXPECT_THROW(KeysetPlanner::Plan(invalid_rotation_zero), ParameterException);

  KeysetRequest invalid_rotation_large;
  invalid_rotation_large.params = params;
  invalid_rotation_large.column_rotations = {params->degree() / 2};
  EXPECT_THROW(KeysetPlanner::Plan(invalid_rotation_large), ParameterException);

  KeysetRequest invalid_levels;
  invalid_levels.params = params;
  invalid_levels.ciphertext_level = 0;
  invalid_levels.evaluation_key_level = 1;
  EXPECT_THROW(KeysetPlanner::Plan(invalid_levels), ParameterException);
}

TEST_F(KeysetPlannerTest, RejectsMismatchedSecretKeyWhenBuildingKeys) {
  auto params_a = MakeParams();
  auto params_b = BfvParameters::default_arc(5, 16);
  auto sk_b = SecretKey::random(params_b, rng_);

  KeysetRequest request;
  request.params = params_a;
  request.column_rotations = {1};

  auto plan = KeysetPlanner::Plan(request);
  EXPECT_THROW(KeysetPlanner::BuildEvaluationKey(sk_b, plan, rng_),
               ParameterException);
}

TEST_F(KeysetPlannerTest, PlansFromWorkloadProfile) {
  auto params = MakeParams();

  WorkloadProfile profile;
  profile.params = params;
  profile.num_ciphertext_multiplications = 3;
  profile.num_inner_sum_ops = 2;
  profile.max_expansion_level = 1;
  profile.column_rotation_histogram = {
      RotationUse{1, 7},
      RotationUse{3, 4},
      RotationUse{1, 2},
      RotationUse{5, 0},
  };

  auto plan = KeysetPlanner::Plan(profile);

  EXPECT_TRUE(plan.needs_relinearization);
  EXPECT_TRUE(plan.needs_inner_sum);
  EXPECT_TRUE(plan.needs_row_rotation);
  EXPECT_EQ(plan.requested_column_rotations, (std::vector<size_t>{1, 3}));
  EXPECT_EQ(plan.implied_column_rotations, (std::vector<size_t>{1, 2, 4}));
  EXPECT_EQ(plan.effective_column_rotations, (std::vector<size_t>{1, 2, 3, 4}));
  EXPECT_EQ(plan.profiled_rotation_uses, 13u);
  EXPECT_EQ(plan.profiled_inner_sum_uses, 2u);
  EXPECT_NE(plan.Summary().find("profiled_rotation_uses=13"),
            std::string::npos);
  EXPECT_NE(plan.Summary().find("profiled_inner_sum_uses=2"),
            std::string::npos);
}

TEST_F(KeysetPlannerTest, ProfilePlanningMatchesEquivalentRequest) {
  auto params = MakeParams();

  WorkloadProfile profile;
  profile.params = params;
  profile.num_ciphertext_multiplications = 1;
  profile.require_row_rotation = true;
  profile.max_expansion_level = 2;
  profile.column_rotation_histogram = {
      RotationUse{3, 8},
      RotationUse{1, 1},
      RotationUse{3, 0},
  };

  KeysetRequest request;
  request.params = params;
  request.num_ciphertext_multiplications = 1;
  request.require_row_rotation = true;
  request.max_expansion_level = 2;
  request.column_rotations = {3, 1};

  auto plan_from_profile = KeysetPlanner::Plan(profile);
  auto plan_from_request = KeysetPlanner::Plan(request);

  EXPECT_EQ(plan_from_profile.needs_relinearization,
            plan_from_request.needs_relinearization);
  EXPECT_EQ(plan_from_profile.needs_row_rotation,
            plan_from_request.needs_row_rotation);
  EXPECT_EQ(plan_from_profile.max_expansion_level,
            plan_from_request.max_expansion_level);
  EXPECT_EQ(plan_from_profile.effective_column_rotations,
            plan_from_request.effective_column_rotations);
  EXPECT_EQ(plan_from_profile.effective_galois_elements,
            plan_from_request.effective_galois_elements);
  EXPECT_EQ(plan_from_profile.estimated_total_key_bytes,
            plan_from_request.estimated_total_key_bytes);
}

}  // namespace bfv
}  // namespace crypto
