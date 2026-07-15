#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "heu/experimental/bfv/crypto/encoding.h"
#include "heu/experimental/bfv/crypto/multiplicator.h"
#include "heu/experimental/bfv/crypto/plaintext.h"
#include "heu/experimental/bfv/crypto/secret_key.h"
#include "heu/experimental/bfv/util/bfv_deployment_planner.h"

using namespace crypto::bfv;

namespace {

void Require(bool condition, const std::string &message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

void PrintVectorPrefix(const std::string &label,
                       const std::vector<uint64_t> &values,
                       size_t prefix_len = 8) {
  const size_t count = std::min(prefix_len, values.size());
  std::cout << label << ": [";
  for (size_t i = 0; i < count; ++i) {
    if (i != 0) {
      std::cout << ", ";
    }
    std::cout << values[i];
  }
  if (values.size() > count) {
    std::cout << ", ...";
  }
  std::cout << "]" << std::endl;
}

}  // namespace

int main() {
  std::cout << "=== BFV Deployment Planner Demo ===\n" << std::endl;

  BfvDeploymentRequest request;
  request.plaintext_modulus = 65537;
  request.mul_depth = 1;
  request.workload.num_ciphertext_multiplications = 1;
  request.workload.num_inner_sum_ops = 1;
  request.workload.batch_size = 64;
  request.workload.ciphertext_fan_out = 2;
  request.workload.column_rotation_histogram = {
      RotationUse{1, 6},
      RotationUse{3, 2},
  };

  auto plan = BfvDeploymentPlanner::Plan(request);

  std::cout << "Summary: " << plan.Summary() << std::endl;
  std::cout << "Compiled backend: " << plan.compiled_mul_backend << std::endl;
  std::cout << "Recommended backend: " << plan.recommended_mul_backend
            << std::endl;
  if (!plan.warnings.empty()) {
    std::cout << "Warnings:" << std::endl;
    for (const auto &warning : plan.warnings) {
      std::cout << "  - " << warning << std::endl;
    }
  }
  std::cout << "JSON Report:\n" << plan.ToJson() << "\n" << std::endl;

  std::mt19937_64 rng(42);
  auto params = plan.parameter_plan.params;
  auto secret_key = SecretKey::random(params, rng);

  Require(plan.keyset_plan.requires_evaluation_key(),
          "expected the planned workload to require an evaluation key");
  auto evaluation_key =
      KeysetPlanner::BuildEvaluationKey(secret_key, plan.keyset_plan, rng);
  auto maybe_relin_key =
      KeysetPlanner::BuildRelinearizationKey(secret_key, plan.keyset_plan, rng);
  Require(maybe_relin_key.has_value(),
          "expected the planned workload to require a relinearization key");

  std::cout << "[Keys] supports inner sum: "
            << (evaluation_key.supports_inner_sum() ? "yes" : "no")
            << ", supports rotation by 1: "
            << (evaluation_key.supports_column_rotation_by(1) ? "yes" : "no")
            << ", supports rotation by 3: "
            << (evaluation_key.supports_column_rotation_by(3) ? "yes" : "no")
            << std::endl;

  std::vector<uint64_t> values(params->degree(), 0);
  for (size_t i = 0; i < std::min<size_t>(8, values.size()); ++i) {
    values[i] = static_cast<uint64_t>(i + 1);
  }

  auto plaintext = Plaintext::encode(values, Encoding::simd(), params);
  auto ciphertext = secret_key.encrypt(plaintext, rng);

  auto inner_sum_ct = evaluation_key.computes_inner_sum(ciphertext);
  auto inner_sum_pt = secret_key.decrypt(inner_sum_ct, Encoding::simd());
  auto inner_sum_values = inner_sum_pt.decode_uint64(Encoding::simd());

  uint64_t expected_sum = 0;
  for (uint64_t value : values) {
    expected_sum = (expected_sum + value) % params->plaintext_modulus();
  }
  std::vector<uint64_t> expected_inner_sum(values.size(), expected_sum);
  Require(inner_sum_values == expected_inner_sum,
          "planned inner sum did not match the expected result");
  PrintVectorPrefix("Inner sum result", inner_sum_values);

  auto multiplicator = Multiplicator::create_default(*maybe_relin_key);
  auto squared_ct = multiplicator->multiply(ciphertext, ciphertext);
  auto squared_pt = secret_key.decrypt(squared_ct, Encoding::simd());
  auto squared_values = squared_pt.decode_uint64(Encoding::simd());

  std::vector<uint64_t> expected_squared(values.size(), 0);
  for (size_t i = 0; i < values.size(); ++i) {
    expected_squared[i] = (values[i] * values[i]) % params->plaintext_modulus();
  }
  Require(squared_values == expected_squared,
          "planned multiplication did not match the expected result");
  PrintVectorPrefix("Square result", squared_values);

  return 0;
}
