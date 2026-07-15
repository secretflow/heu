#include "crypto/keyset_planner.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include "crypto/bfv_parameters.h"
#include "crypto/evaluation_key.h"
#include "crypto/exceptions.h"
#include "crypto/relinearization_key.h"
#include "crypto/secret_key.h"
#include "math/modulus.h"

namespace crypto {
namespace bfv {

namespace {

std::vector<size_t> SortAndUnique(std::vector<size_t> values) {
  std::sort(values.begin(), values.end());
  values.erase(std::unique(values.begin(), values.end()), values.end());
  return values;
}

bool ContainsSorted(const std::vector<size_t> &values, size_t needle) {
  return std::binary_search(values.begin(), values.end(), needle);
}

size_t ComputeMaxExpansionLevel(size_t degree) {
  return 64 - __builtin_clzll(static_cast<unsigned long long>(degree));
}

std::vector<size_t> ComputeInnerSumRotations(size_t degree) {
  std::vector<size_t> rotations;
  for (size_t step = 1; step < degree / 2; step <<= 1) {
    rotations.push_back(step);
  }
  return rotations;
}

std::vector<size_t> BuildEffectiveGaloisElements(const KeysetPlan &plan,
                                                 size_t degree) {
  std::unordered_set<size_t> exponents;

  auto q_opt = ::bfv::math::zq::Modulus::New(2 * degree);
  if (!q_opt) {
    throw ParameterException(
        "Failed to build rotation modulus for keyset plan");
  }

  for (size_t step : plan.effective_column_rotations) {
    exponents.insert(static_cast<size_t>(q_opt->Pow(3, step)));
  }

  if (plan.needs_row_rotation) {
    exponents.insert(degree * 2 - 1);
  }

  for (size_t level = 0; level < plan.max_expansion_level; ++level) {
    exponents.insert((degree >> level) + 1);
  }

  std::vector<size_t> result(exponents.begin(), exponents.end());
  std::sort(result.begin(), result.end());
  return result;
}

size_t ComputeSingleKeySwitchKeyBytes(std::shared_ptr<BfvParameters> params,
                                      size_t ciphertext_level,
                                      size_t key_level) {
  auto ctx_ciphertext = params->ctx_at_level(ciphertext_level);
  auto ctx_ksk = params->ctx_at_level(key_level);

  size_t c1_size = 0;
  if (ctx_ksk->moduli().size() == 1) {
    uint64_t modulus = ctx_ksk->moduli()[0];
    uint64_t next_power_of_two = 1;
    while (next_power_of_two < modulus) {
      next_power_of_two <<= 1;
    }

    size_t log_modulus = 0;
    for (uint64_t value = next_power_of_two; value > 1; value >>= 1) {
      ++log_modulus;
    }

    size_t log_base = std::max<size_t>(1, log_modulus / 2);
    c1_size = (log_modulus + log_base - 1) / log_base;
  } else {
    c1_size = ctx_ciphertext->moduli().size();
  }

  const size_t degree = params->degree();
  const size_t ksk_moduli = ctx_ksk->moduli().size();

  // This estimates the raw coefficient payload for c0/c1 polynomial rows.
  return 2 * c1_size * degree * ksk_moduli * sizeof(uint64_t);
}

bool SameParameters(const std::shared_ptr<BfvParameters> &lhs,
                    const std::shared_ptr<BfvParameters> &rhs) {
  if (!lhs || !rhs) {
    return false;
  }
  return lhs == rhs || *lhs == *rhs;
}

KeysetRequest RequestFromProfile(const WorkloadProfile &profile) {
  KeysetRequest request;
  request.params = profile.params;
  request.ciphertext_level = profile.ciphertext_level;
  request.evaluation_key_level = profile.evaluation_key_level;
  request.num_ciphertext_multiplications =
      profile.num_ciphertext_multiplications;
  request.require_row_rotation = profile.require_row_rotation;
  request.require_inner_sum = profile.num_inner_sum_ops > 0;
  request.max_expansion_level = profile.max_expansion_level;

  request.column_rotations.reserve(profile.column_rotation_histogram.size());
  for (const auto &rotation : profile.column_rotation_histogram) {
    if (rotation.count == 0) {
      continue;
    }
    request.column_rotations.push_back(rotation.steps);
  }

  return request;
}

std::vector<RotationUse> BuildRankedRotationHistogram(
    const std::vector<RotationUse> &histogram) {
  std::unordered_map<size_t, size_t> counts_by_step;
  for (const auto &rotation : histogram) {
    if (rotation.count == 0) {
      continue;
    }
    counts_by_step[rotation.steps] += rotation.count;
  }

  std::vector<RotationUse> ranked;
  ranked.reserve(counts_by_step.size());
  for (const auto &[steps, count] : counts_by_step) {
    ranked.push_back(RotationUse{steps, count});
  }

  std::sort(ranked.begin(), ranked.end(),
            [](const RotationUse &lhs, const RotationUse &rhs) {
              if (lhs.count != rhs.count) {
                return lhs.count > rhs.count;
              }
              return lhs.steps < rhs.steps;
            });
  return ranked;
}

void ValidateRequest(const KeysetRequest &request) {
  if (!request.params) {
    throw ParameterException("KeysetRequest requires non-null BFV parameters");
  }

  const size_t max_level = request.params->max_level();
  if (request.ciphertext_level > max_level) {
    throw ParameterException("Ciphertext level exceeds parameter max level");
  }
  if (request.evaluation_key_level > request.ciphertext_level) {
    throw ParameterException(
        "Evaluation key level cannot exceed ciphertext level");
  }

  const size_t degree = request.params->degree();
  const size_t max_rotation_steps = degree / 2;
  for (size_t step : request.column_rotations) {
    if (step == 0) {
      throw ParameterException("Column rotation steps cannot be 0");
    }
    if (step >= max_rotation_steps) {
      throw ParameterException("Column rotation steps must be less than " +
                               std::to_string(max_rotation_steps));
    }
  }

  const size_t max_expansion = ComputeMaxExpansionLevel(degree);
  if (request.max_expansion_level >= max_expansion) {
    throw ParameterException(
        "Expansion level " + std::to_string(request.max_expansion_level) +
        " must be less than " + std::to_string(max_expansion));
  }
}

}  // namespace

std::string KeysetPlan::Summary() const {
  std::ostringstream oss;
  oss << "KeysetPlan{"
      << "ct_level=" << ciphertext_level
      << ", ek_level=" << evaluation_key_level
      << ", relin=" << (needs_relinearization ? "yes" : "no")
      << ", row_rotation=" << (needs_row_rotation ? "yes" : "no")
      << ", inner_sum=" << (needs_inner_sum ? "yes" : "no")
      << ", column_rotations=" << effective_column_rotations.size()
      << ", expansion_level=" << max_expansion_level
      << ", galois_keys=" << estimated_galois_key_count
      << ", profiled_rotation_uses=" << profiled_rotation_uses
      << ", profiled_inner_sum_uses=" << profiled_inner_sum_uses
      << ", batch_size=" << profiled_batch_size
      << ", ciphertext_fan_out=" << profiled_ciphertext_fan_out
      << ", estimated_total_key_bytes=" << estimated_total_key_bytes << "}";
  return oss.str();
}

KeysetPlan KeysetPlanner::Plan(const KeysetRequest &request) {
  ValidateRequest(request);

  KeysetPlan plan;
  plan.params = request.params;
  plan.ciphertext_level = request.ciphertext_level;
  plan.evaluation_key_level = request.evaluation_key_level;
  plan.needs_relinearization = request.num_ciphertext_multiplications > 0;
  plan.needs_inner_sum = request.require_inner_sum;
  plan.needs_row_rotation =
      request.require_row_rotation || request.require_inner_sum;
  plan.max_expansion_level = request.max_expansion_level;
  plan.requested_column_rotations = SortAndUnique(request.column_rotations);
  if (plan.needs_inner_sum) {
    plan.implied_column_rotations =
        ComputeInnerSumRotations(request.params->degree());
  }

  plan.effective_column_rotations = plan.requested_column_rotations;
  plan.effective_column_rotations.insert(plan.effective_column_rotations.end(),
                                         plan.implied_column_rotations.begin(),
                                         plan.implied_column_rotations.end());
  plan.effective_column_rotations =
      SortAndUnique(std::move(plan.effective_column_rotations));

  plan.effective_galois_elements =
      BuildEffectiveGaloisElements(plan, request.params->degree());
  plan.estimated_galois_key_count = plan.effective_galois_elements.size();

  const size_t single_key_switch_bytes = ComputeSingleKeySwitchKeyBytes(
      request.params, request.ciphertext_level, request.evaluation_key_level);
  plan.estimated_galois_key_bytes =
      single_key_switch_bytes * plan.estimated_galois_key_count;
  plan.estimated_relinearization_key_bytes =
      plan.needs_relinearization ? single_key_switch_bytes : 0;
  plan.estimated_total_key_bytes = plan.estimated_galois_key_bytes +
                                   plan.estimated_relinearization_key_bytes;

  return plan;
}

KeysetPlan KeysetPlanner::Plan(const WorkloadProfile &profile) {
  auto plan = Plan(RequestFromProfile(profile));
  for (const auto &rotation : profile.column_rotation_histogram) {
    plan.profiled_rotation_uses += rotation.count;
  }
  plan.profiled_inner_sum_uses = profile.num_inner_sum_ops;
  plan.profiled_batch_size = std::max<size_t>(1, profile.batch_size);
  plan.profiled_ciphertext_fan_out =
      std::max<size_t>(1, profile.ciphertext_fan_out);
  plan.ranked_column_rotations =
      BuildRankedRotationHistogram(profile.column_rotation_histogram);
  return plan;
}

EvaluationKey KeysetPlanner::BuildEvaluationKey(const SecretKey &secret_key,
                                                const KeysetPlan &plan,
                                                std::mt19937_64 &rng) {
  if (!plan.requires_evaluation_key()) {
    throw ParameterException("Keyset plan does not require an evaluation key");
  }
  if (!SameParameters(secret_key.parameters(), plan.params)) {
    throw ParameterException(
        "Secret key parameters do not match the keyset plan");
  }

  auto builder = EvaluationKeyBuilder::create_leveled(
      secret_key, plan.ciphertext_level, plan.evaluation_key_level);

  if (plan.needs_inner_sum) {
    builder.enable_inner_sum();
  } else if (plan.needs_row_rotation) {
    builder.enable_row_rotation();
  }

  for (size_t step : plan.requested_column_rotations) {
    if (plan.needs_inner_sum &&
        ContainsSorted(plan.implied_column_rotations, step)) {
      continue;
    }
    builder.enable_column_rotation(step);
  }

  if (plan.max_expansion_level != 0) {
    builder.enable_expansion(plan.max_expansion_level);
  }

  return builder.build(rng);
}

std::optional<RelinearizationKey> KeysetPlanner::BuildRelinearizationKey(
    const SecretKey &secret_key, const KeysetPlan &plan, std::mt19937_64 &rng) {
  if (!plan.needs_relinearization) {
    return std::nullopt;
  }
  if (!SameParameters(secret_key.parameters(), plan.params)) {
    throw ParameterException(
        "Secret key parameters do not match the keyset plan");
  }

  return RelinearizationKey::from_secret_key_leveled(
      secret_key, plan.ciphertext_level, plan.evaluation_key_level, rng);
}

}  // namespace bfv
}  // namespace crypto
