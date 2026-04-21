#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "heu/experimental/bfv/crypto/bfv_parameters.h"
#include "heu/experimental/bfv/crypto/encoding.h"
#include "heu/experimental/bfv/crypto/keyset_planner.h"
#include "heu/experimental/bfv/crypto/plaintext.h"
#include "heu/experimental/bfv/crypto/secret_key.h"

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

std::vector<uint64_t> RotateColumnsExpected(const std::vector<uint64_t> &values,
                                            size_t steps) {
  const size_t row_size = values.size() / 2;
  std::vector<uint64_t> expected(values.size(), 0);

  for (size_t idx = 0; idx < row_size - steps; ++idx) {
    expected[idx] = values[steps + idx];
  }
  for (size_t idx = 0; idx < steps; ++idx) {
    expected[row_size - steps + idx] = values[idx];
  }
  for (size_t idx = 0; idx < row_size - steps; ++idx) {
    expected[row_size + idx] = values[row_size + steps + idx];
  }
  for (size_t idx = 0; idx < steps; ++idx) {
    expected[2 * row_size - steps + idx] = values[row_size + idx];
  }

  return expected;
}

}  // namespace

int main() {
  std::cout << "=== BFV Keyset Planner Demo ===\n" << std::endl;

  auto params = BfvParameters::default_arc(6, 16);

  KeysetRequest request;
  request.params = params;
  request.num_ciphertext_multiplications = 1;
  request.require_inner_sum = true;
  request.max_expansion_level = 2;
  request.column_rotations = {1, 3};

  WorkloadProfile profile;
  profile.params = params;
  profile.num_ciphertext_multiplications = 1;
  profile.num_inner_sum_ops = 1;
  profile.max_expansion_level = 2;
  profile.batch_size = 128;
  profile.ciphertext_fan_out = 3;
  profile.column_rotation_histogram = {
      RotationUse{3, 8},
      RotationUse{1, 2},
      RotationUse{3, 0},
  };

  auto request_plan = KeysetPlanner::Plan(request);
  auto profile_plan = KeysetPlanner::Plan(profile);

  std::cout << "Request plan: " << request_plan.Summary() << std::endl;
  std::cout << "Profile plan: " << profile_plan.Summary() << "\n" << std::endl;

  std::mt19937_64 rng(42);
  auto secret_key = SecretKey::random(params, rng);
  auto evaluation_key =
      KeysetPlanner::BuildEvaluationKey(secret_key, profile_plan, rng);
  auto maybe_relin_key =
      KeysetPlanner::BuildRelinearizationKey(secret_key, profile_plan, rng);

  std::cout << "[Keys] supports inner sum: "
            << (evaluation_key.supports_inner_sum() ? "yes" : "no")
            << ", supports rotation by 3: "
            << (evaluation_key.supports_column_rotation_by(3) ? "yes" : "no")
            << ", supports expansion(2): "
            << (evaluation_key.supports_expansion(2) ? "yes" : "no")
            << ", has relinearization key: "
            << (maybe_relin_key.has_value() ? "yes" : "no") << std::endl;

  std::vector<uint64_t> values(params->degree(), 0);
  for (size_t i = 0; i < values.size(); ++i) {
    values[i] = static_cast<uint64_t>(i + 1);
  }

  auto plaintext = Plaintext::encode(values, Encoding::simd(), params);
  auto ciphertext = secret_key.encrypt(plaintext, rng);

  auto rotated_ct = evaluation_key.rotates_columns_by(ciphertext, 3);
  auto rotated_pt = secret_key.decrypt(rotated_ct, Encoding::simd());
  auto rotated_values = rotated_pt.decode_uint64(Encoding::simd());
  auto expected_rotated = RotateColumnsExpected(values, 3);
  Require(rotated_values == expected_rotated,
          "column rotation by 3 did not match the expected result");
  PrintVectorPrefix("Rotate-by-3 result", rotated_values);

  auto inner_sum_ct = evaluation_key.computes_inner_sum(ciphertext);
  auto inner_sum_pt = secret_key.decrypt(inner_sum_ct, Encoding::simd());
  auto inner_sum_values = inner_sum_pt.decode_uint64(Encoding::simd());

  uint64_t expected_sum = 0;
  for (uint64_t value : values) {
    expected_sum = (expected_sum + value) % params->plaintext_modulus();
  }
  std::vector<uint64_t> expected_inner_sum(values.size(), expected_sum);
  Require(inner_sum_values == expected_inner_sum,
          "inner sum did not match the expected result");
  PrintVectorPrefix("Inner sum result", inner_sum_values);

  return 0;
}
