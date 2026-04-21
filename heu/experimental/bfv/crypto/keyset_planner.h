#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "crypto/evaluation_key.h"
#include "crypto/relinearization_key.h"

namespace crypto {
namespace bfv {

class BfvParameters;
class SecretKey;

struct RotationUse {
  size_t steps = 0;
  size_t count = 0;
};

struct KeysetRequest {
  std::shared_ptr<BfvParameters> params;
  size_t ciphertext_level = 0;
  size_t evaluation_key_level = 0;

  // A non-zero multiplication count implies that a relinearization key is
  // required by the workload.
  size_t num_ciphertext_multiplications = 0;

  bool require_row_rotation = false;
  bool require_inner_sum = false;
  size_t max_expansion_level = 0;

  // Requested column rotations in SIMD space.
  std::vector<size_t> column_rotations;
};

struct WorkloadProfile {
  std::shared_ptr<BfvParameters> params;
  size_t ciphertext_level = 0;
  size_t evaluation_key_level = 0;

  size_t num_ciphertext_multiplications = 0;
  size_t num_relinearizations = 0;
  size_t num_inner_sum_ops = 0;
  bool require_row_rotation = false;
  size_t max_expansion_level = 0;
  size_t ciphertext_fan_out = 1;
  size_t batch_size = 1;

  // Profiled column rotations with occurrence counts. Entries with `count == 0`
  // are ignored by the planner.
  std::vector<RotationUse> column_rotation_histogram;
};

struct KeysetPlan {
  std::shared_ptr<BfvParameters> params;
  size_t ciphertext_level = 0;
  size_t evaluation_key_level = 0;

  bool needs_relinearization = false;
  bool needs_row_rotation = false;
  bool needs_inner_sum = false;
  size_t max_expansion_level = 0;

  // User-requested rotations after sorting and deduplication.
  std::vector<size_t> requested_column_rotations;

  // Rotations implied by higher-level capabilities such as inner sum.
  std::vector<size_t> implied_column_rotations;

  // Full effective rotation set after merging requested and implied rotations.
  std::vector<size_t> effective_column_rotations;

  // Distinct Galois exponents required to materialize the plan.
  std::vector<size_t> effective_galois_elements;

  size_t estimated_galois_key_count = 0;
  size_t estimated_galois_key_bytes = 0;
  size_t estimated_relinearization_key_bytes = 0;
  size_t estimated_total_key_bytes = 0;
  size_t profiled_rotation_uses = 0;
  size_t profiled_inner_sum_uses = 0;
  size_t profiled_batch_size = 1;
  size_t profiled_ciphertext_fan_out = 1;

  // Rotation histogram aggregated by step and ranked by hotness.
  std::vector<RotationUse> ranked_column_rotations;

  bool requires_evaluation_key() const {
    return !effective_galois_elements.empty();
  }

  std::string Summary() const;
};

class KeysetPlanner {
 public:
  static KeysetPlan Plan(const KeysetRequest &request);
  static KeysetPlan Plan(const WorkloadProfile &profile);

  static EvaluationKey BuildEvaluationKey(const SecretKey &secret_key,
                                          const KeysetPlan &plan,
                                          std::mt19937_64 &rng);

  static std::optional<RelinearizationKey> BuildRelinearizationKey(
      const SecretKey &secret_key, const KeysetPlan &plan,
      std::mt19937_64 &rng);
};

}  // namespace bfv
}  // namespace crypto
