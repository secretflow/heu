#include "util/bfv_param_advisor.h"

#include "crypto/bfv_parameters.h"
#include "crypto/exceptions.h"
#include "gtest/gtest.h"

namespace crypto::bfv {

TEST(BfvParamAdvisorTest, CommonParams) {
  ParamAdvisorRequest req;
  req.plaintext_nbits =
      20;  // Increased to 20 to find a valid NTT prime for degree 8192
  req.mul_depth = 2;

  auto res = BfvParamAdvisor::Recommend(req);

  EXPECT_NE(res.params, nullptr);
  // LogQ required = (20+10) + 2*35 + 20 = 30 + 70 + 20 = 120.
  // Max for 4096 is 109. Expect degree 8192 (max 218).
  EXPECT_EQ(res.report.chosen_degree, 8192);

  EXPECT_EQ(res.report.pt_bits, 20);
  EXPECT_LE(res.report.logq_required, res.report.logq_max_allowed);

  size_t sum = 0;
  for (auto s : res.report.moduli_sizes) {
    EXPECT_GE(s, 10);
    EXPECT_LE(s, 62);
    sum += s;
  }
  EXPECT_EQ(sum, res.report.logq_actual);

  // Verify params actually built
  EXPECT_EQ(res.params->degree(), res.report.chosen_degree);
  // Check bit length is 20
  EXPECT_EQ(res.report.pt_bits, 20);
  EXPECT_GT(res.params->plaintext_modulus(), 1ULL << 19);
  EXPECT_LT(res.params->plaintext_modulus(), 1ULL << 20);
}

TEST(BfvParamAdvisorTest, DepthTooLarge) {
  ParamAdvisorRequest req;
  req.plaintext_nbits = 32;
  req.mul_depth = 20;  // logq = 32+10 + 700 + 20 = 762 > 438 (max for 16384)

  try {
    BfvParamAdvisor::Recommend(req);
    FAIL() << "Expected ParameterException";
  } catch (const ParameterException &e) {
    std::string msg = e.what();
    EXPECT_NE(msg.find("exceeds maximum supported"), std::string::npos);
  } catch (...) {
    FAIL() << "Expected ParameterException";
  }
}

TEST(BfvParamAdvisorTest, InvalidInput) {
  // Both 0
  {
    ParamAdvisorRequest req;
    EXPECT_THROW(BfvParamAdvisor::Recommend(req), ParameterException);
  }
  // Both set
  {
    ParamAdvisorRequest req;
    req.plaintext_nbits = 16;
    req.plaintext_modulus = 65537;
    EXPECT_THROW(BfvParamAdvisor::Recommend(req), ParameterException);
  }
}

TEST(BfvParamAdvisorTest, PlaintextModulusProvided) {
  ParamAdvisorRequest req;
  req.plaintext_modulus = 65537;  // 17 bits
  req.mul_depth = 1;

  auto res = BfvParamAdvisor::Recommend(req);
  EXPECT_EQ(res.params->plaintext_modulus(), 65537);
  EXPECT_EQ(res.report.pt_bits, 17);
}

TEST(BfvParamAdvisorTest, AdvancedParamsWithProfile) {
  ParamAdvisorRequest req;
  req.plaintext_nbits = 20;
  req.mul_depth = 5;
  req.op_profile = {5, 2, 2};

  auto res = BfvParamAdvisor::Recommend(req);

  EXPECT_EQ(res.report.inferred_mul_depth, 3u);
  EXPECT_EQ(res.report.effective_mul_depth, 5u);
  EXPECT_EQ(res.report.profile_penalty_bits, 5u);
  EXPECT_EQ(res.report.logq_required, 230u);
  EXPECT_EQ(res.report.chosen_degree, 16384);

  // Check JSON output
  std::string json = res.report.ToJson();
  EXPECT_NE(json.find("\"chosen_degree\": 16384"), std::string::npos);
  EXPECT_NE(json.find("\"effective_mul_depth\": 5"), std::string::npos);
  EXPECT_NE(json.find("\"estimated_ciphertext_bytes\":"), std::string::npos);
}

TEST(BfvParamAdvisorTest, ProfileOnlyCanInferDepth) {
  ParamAdvisorRequest req;
  req.plaintext_nbits = 20;
  req.op_profile = {8, 4, 12};

  auto res = BfvParamAdvisor::Recommend(req);

  EXPECT_EQ(res.report.inferred_mul_depth, 4u);
  EXPECT_EQ(res.report.effective_mul_depth, 4u);
  EXPECT_EQ(res.report.profile_penalty_bits, 18u);
  EXPECT_EQ(res.report.logq_required, 208u);
  EXPECT_EQ(res.report.chosen_degree, 8192u);
  ASSERT_FALSE(res.report.warnings.empty());
  EXPECT_NE(res.report.warnings[0].find("inferred effective depth 4"),
            std::string::npos);
}

TEST(BfvParamAdvisorTest, ProfileCanRaiseTooSmallDepth) {
  ParamAdvisorRequest req;
  req.plaintext_nbits = 20;
  req.mul_depth = 2;
  req.op_profile = {15, 0, 0};

  auto res = BfvParamAdvisor::Recommend(req);

  EXPECT_EQ(res.report.inferred_mul_depth, 4u);
  EXPECT_EQ(res.report.effective_mul_depth, 4u);
  EXPECT_EQ(res.report.profile_penalty_bits, 15u);
  EXPECT_EQ(res.report.logq_required, 205u);
  EXPECT_EQ(res.report.chosen_degree, 8192u);
  ASSERT_FALSE(res.report.warnings.empty());
  EXPECT_NE(res.report.warnings[0].find("effective depth 4"),
            std::string::npos);
}

// ... (OptimizationStrategies, MisuseResistance, MemoryEstimation tests are
// fine)

TEST(BfvParamAdvisorTest, OptimizationStrategies) {
  ParamAdvisorRequest req;
  req.plaintext_nbits = 20;
  req.mul_depth = 2;  // base 70 + 30 + 20=120

  // Fast strategy: margin 10. -> 110.
  req.strategy = OptimizationStrategy::kFast;
  auto res_fast = BfvParamAdvisor::Recommend(req);
  EXPECT_EQ(res_fast.report.logq_required, 110);
}

TEST(BfvParamAdvisorTest, MisuseResistance_BadP) {
  ParamAdvisorRequest req;
  req.plaintext_modulus = 65537;
  req.mul_depth = 1;
  auto res = BfvParamAdvisor::Recommend(req);
  EXPECT_EQ(res.report.chosen_degree, 4096);

  req.plaintext_modulus = 65539;
  EXPECT_THROW(BfvParamAdvisor::Recommend(req), ParameterException);
}

TEST(BfvParamAdvisorTest, MemoryEstimation) {
  ParamAdvisorRequest req;
  req.plaintext_nbits = 20;
  req.mul_depth = 1;
  auto res = BfvParamAdvisor::Recommend(req);
  EXPECT_EQ(res.report.estimated_ciphertext_bytes, 131072);
}

TEST(BfvParamAdvisorTest, SelfTestCheck) {
  ParamAdvisorRequest req;
  req.plaintext_nbits = 20;
  req.mul_depth = 1;
  auto res = BfvParamAdvisor::Recommend(req);

  std::string report;
  bool ok = res.params->SelfTest(&report);
  EXPECT_TRUE(ok);
  EXPECT_NE(report.find("Starting SelfTest for BFV Parameters"),
            std::string::npos);
  EXPECT_NE(report.find("OK"), std::string::npos);
}

}  // namespace crypto::bfv
