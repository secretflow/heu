#include "util/backend_autotuner.h"

#include <algorithm>
#include <sstream>

#include "crypto/exceptions.h"
#include "math/residue_transfer_engine.h"

namespace crypto::bfv {

namespace {

size_t SumRotationUses(const WorkloadProfile &profile) {
  size_t total = 0;
  for (const auto &rotation : profile.column_rotation_histogram) {
    total += rotation.count;
  }
  return total;
}

std::string SchemeName(::bfv::math::rns::RnsScalingScheme scheme) {
  switch (scheme) {
    case ::bfv::math::rns::RnsScalingScheme::AuxBase:
      return "aux_base";
    case ::bfv::math::rns::RnsScalingScheme::ResidueTransfer:
      return "residue_transfer";
  }
  return "unknown";
}

std::string RecommendBackendName(const BackendAutotuningRequest &request) {
  const auto &workload = request.workload;
  const size_t degree = request.params->degree();
  const size_t batch_size = std::max<size_t>(1, workload.batch_size);
  const size_t fan_out = std::max<size_t>(1, workload.ciphertext_fan_out);

  if (degree >= 8192 || batch_size >= 128 || fan_out >= 4 ||
      workload.num_ciphertext_multiplications >= 2) {
    return "aux_base_candidate";
  }

  return "residue_transfer_candidate";
}

std::string BuildReason(const BackendAutotuningRequest &request,
                        const std::string &recommendation) {
  std::ostringstream oss;
  oss << "degree=" << request.params->degree()
      << ", batch_size=" << std::max<size_t>(1, request.workload.batch_size)
      << ", ciphertext_fan_out="
      << std::max<size_t>(1, request.workload.ciphertext_fan_out)
      << ", num_mul=" << request.workload.num_ciphertext_multiplications
      << " -> " << recommendation;
  return oss.str();
}

double EstimateLatencyScore(const BackendAutotuningRequest &request) {
  const auto &workload = request.workload;
  const double degree_factor =
      static_cast<double>(request.params->degree()) / 4096.0;
  const double mul_factor =
      1.0 + static_cast<double>(workload.num_ciphertext_multiplications) * 3.0;
  const double rotation_factor =
      1.0 + static_cast<double>(SumRotationUses(workload)) * 0.15 +
      static_cast<double>(workload.num_inner_sum_ops) * 0.75;
  const double fanout_factor =
      1.0 + static_cast<double>(
                std::max<size_t>(1, workload.ciphertext_fan_out) - 1) *
                0.25;
  const double batch_factor =
      1.0 +
      static_cast<double>(
          std::max<size_t>(1, request.estimated_batch_ciphertext_count) - 1) *
          0.20;
  return degree_factor * mul_factor * rotation_factor * fanout_factor *
         batch_factor;
}

void ValidateRequest(const BackendAutotuningRequest &request) {
  if (!request.params) {
    throw ParameterException(
        "BackendAutotuningRequest requires non-null BFV parameters");
  }
}

}  // namespace

BackendAutotuningDecision BackendAutotuner::Recommend(
    const BackendAutotuningRequest &request) {
  ValidateRequest(request);

  BackendAutotuningDecision decision;
  decision.compiled_backend =
      SchemeName(request.params->mul_rns_scaling_scheme());
  decision.recommended_backend = RecommendBackendName(request);
  decision.reason = BuildReason(request, decision.recommended_backend);
  decision.estimated_latency_score = EstimateLatencyScore(request);
  return decision;
}

}  // namespace crypto::bfv
