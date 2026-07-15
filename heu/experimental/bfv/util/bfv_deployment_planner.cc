#include "util/bfv_deployment_planner.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "util/backend_autotuner.h"

namespace crypto::bfv {

namespace {

size_t SumRotationUses(const WorkloadProfile &profile) {
  size_t total = 0;
  for (const auto &rotation : profile.column_rotation_histogram) {
    total += rotation.count;
  }
  return total;
}

std::string EscapeJson(const std::string &input) {
  std::ostringstream oss;
  for (char ch : input) {
    switch (ch) {
      case '\\':
        oss << "\\\\";
        break;
      case '"':
        oss << "\\\"";
        break;
      case '\n':
        oss << "\\n";
        break;
      case '\r':
        oss << "\\r";
        break;
      case '\t':
        oss << "\\t";
        break;
      default:
        oss << ch;
        break;
    }
  }
  return oss.str();
}

void AppendSizeArray(std::ostringstream &oss,
                     const std::vector<size_t> &values) {
  oss << "[";
  for (size_t i = 0; i < values.size(); ++i) {
    oss << values[i];
    if (i + 1 < values.size()) {
      oss << ", ";
    }
  }
  oss << "]";
}

void AppendRotationHistogram(std::ostringstream &oss,
                             const std::vector<RotationUse> &histogram) {
  oss << "[";
  for (size_t i = 0; i < histogram.size(); ++i) {
    oss << "{"
        << "\"steps\": " << histogram[i].steps << ", "
        << "\"count\": " << histogram[i].count << "}";
    if (i + 1 < histogram.size()) {
      oss << ", ";
    }
  }
  oss << "]";
}

ParamAdvisorRequest BuildAdvisorRequest(const BfvDeploymentRequest &request) {
  ParamAdvisorRequest advisor_request;
  advisor_request.security = request.security;
  advisor_request.strategy = request.strategy;
  advisor_request.plaintext_modulus = request.plaintext_modulus;
  advisor_request.plaintext_nbits = request.plaintext_nbits;
  advisor_request.mul_depth = request.mul_depth;
  advisor_request.variance = request.variance;
  advisor_request.op_profile.num_mul =
      request.workload.num_ciphertext_multiplications;
  advisor_request.op_profile.num_relin =
      std::max(request.workload.num_relinearizations,
               request.workload.num_ciphertext_multiplications);
  advisor_request.op_profile.num_rot =
      SumRotationUses(request.workload) + request.workload.num_inner_sum_ops +
      (request.workload.require_row_rotation ? 1 : 0);
  return advisor_request;
}

size_t EstimateBatchCiphertextCount(const WorkloadProfile &workload,
                                    const ParamAdvisorResult &params_result) {
  const size_t slots = std::max<size_t>(1, params_result.params->degree() / 2);
  const size_t batch_size = std::max<size_t>(1, workload.batch_size);
  return std::max<size_t>(1, (batch_size + slots - 1) / slots);
}

}  // namespace

std::string BfvDeploymentPlan::Summary() const {
  std::ostringstream oss;
  oss << "BfvDeploymentPlan{"
      << "degree="
      << (parameter_plan.params ? parameter_plan.params->degree() : 0)
      << ", ciphertext_bytes=" << estimated_peak_ciphertext_bytes
      << ", key_bytes=" << estimated_total_key_material_bytes
      << ", working_set_bytes=" << estimated_peak_working_set_bytes
      << ", backend=" << recommended_mul_backend
      << ", latency_score=" << estimated_latency_score << "}";
  return oss.str();
}

std::string BfvDeploymentPlan::ToJson() const {
  std::ostringstream oss;
  oss << "{";
  oss << "\"parameters\": " << parameter_plan.report.ToJson() << ", ";
  oss << "\"keyset\": {";
  oss << "\"ciphertext_level\": " << keyset_plan.ciphertext_level << ", ";
  oss << "\"evaluation_key_level\": " << keyset_plan.evaluation_key_level
      << ", ";
  oss << "\"needs_relinearization\": "
      << (keyset_plan.needs_relinearization ? "true" : "false") << ", ";
  oss << "\"needs_row_rotation\": "
      << (keyset_plan.needs_row_rotation ? "true" : "false") << ", ";
  oss << "\"needs_inner_sum\": "
      << (keyset_plan.needs_inner_sum ? "true" : "false") << ", ";
  oss << "\"max_expansion_level\": " << keyset_plan.max_expansion_level << ", ";
  oss << "\"requested_column_rotations\": ";
  AppendSizeArray(oss, keyset_plan.requested_column_rotations);
  oss << ", ";
  oss << "\"implied_column_rotations\": ";
  AppendSizeArray(oss, keyset_plan.implied_column_rotations);
  oss << ", ";
  oss << "\"effective_column_rotations\": ";
  AppendSizeArray(oss, keyset_plan.effective_column_rotations);
  oss << ", ";
  oss << "\"effective_galois_elements\": ";
  AppendSizeArray(oss, keyset_plan.effective_galois_elements);
  oss << ", ";
  oss << "\"estimated_galois_key_count\": "
      << keyset_plan.estimated_galois_key_count << ", ";
  oss << "\"estimated_galois_key_bytes\": "
      << keyset_plan.estimated_galois_key_bytes << ", ";
  oss << "\"estimated_relinearization_key_bytes\": "
      << keyset_plan.estimated_relinearization_key_bytes << ", ";
  oss << "\"estimated_total_key_bytes\": "
      << keyset_plan.estimated_total_key_bytes << ", ";
  oss << "\"profiled_rotation_uses\": " << keyset_plan.profiled_rotation_uses
      << ", ";
  oss << "\"profiled_inner_sum_uses\": " << keyset_plan.profiled_inner_sum_uses
      << ", ";
  oss << "\"profiled_batch_size\": " << keyset_plan.profiled_batch_size << ", ";
  oss << "\"profiled_ciphertext_fan_out\": "
      << keyset_plan.profiled_ciphertext_fan_out << ", ";
  oss << "\"ranked_column_rotations\": ";
  AppendRotationHistogram(oss, keyset_plan.ranked_column_rotations);
  oss << "}, ";
  oss << "\"compiled_mul_backend\": \"" << EscapeJson(compiled_mul_backend)
      << "\", ";
  oss << "\"recommended_mul_backend\": \""
      << EscapeJson(recommended_mul_backend) << "\", ";
  oss << "\"backend_reason\": \"" << EscapeJson(backend_reason) << "\", ";
  oss << "\"estimated_peak_ciphertext_bytes\": "
      << estimated_peak_ciphertext_bytes << ", ";
  oss << "\"estimated_batch_ciphertext_count\": "
      << estimated_batch_ciphertext_count << ", ";
  oss << "\"estimated_total_key_material_bytes\": "
      << estimated_total_key_material_bytes << ", ";
  oss << "\"estimated_peak_working_set_bytes\": "
      << estimated_peak_working_set_bytes << ", ";
  oss << "\"estimated_latency_score\": " << std::setprecision(6)
      << estimated_latency_score << ", ";
  oss << "\"warnings\": [";
  for (size_t i = 0; i < warnings.size(); ++i) {
    oss << "\"" << EscapeJson(warnings[i]) << "\"";
    if (i + 1 < warnings.size()) {
      oss << ", ";
    }
  }
  oss << "]";
  oss << "}";
  return oss.str();
}

BfvDeploymentPlan BfvDeploymentPlanner::Plan(
    const BfvDeploymentRequest &request) {
  auto advisor_request = BuildAdvisorRequest(request);
  auto parameter_plan = BfvParamAdvisor::Recommend(advisor_request);

  WorkloadProfile hydrated_workload = request.workload;
  hydrated_workload.params = parameter_plan.params;

  auto keyset_plan = KeysetPlanner::Plan(hydrated_workload);

  BfvDeploymentPlan plan;
  plan.parameter_plan = std::move(parameter_plan);
  plan.keyset_plan = std::move(keyset_plan);

  const size_t fan_out =
      std::max<size_t>(1, request.workload.ciphertext_fan_out);
  plan.estimated_batch_ciphertext_count =
      EstimateBatchCiphertextCount(request.workload, plan.parameter_plan);
  BackendAutotuningRequest autotuning_request;
  autotuning_request.params = plan.parameter_plan.params;
  autotuning_request.workload = request.workload;
  autotuning_request.estimated_batch_ciphertext_count =
      plan.estimated_batch_ciphertext_count;
  auto backend_decision = BackendAutotuner::Recommend(autotuning_request);
  plan.compiled_mul_backend = std::move(backend_decision.compiled_backend);
  plan.recommended_mul_backend =
      std::move(backend_decision.recommended_backend);
  plan.backend_reason = std::move(backend_decision.reason);
  plan.estimated_latency_score = backend_decision.estimated_latency_score;

  plan.estimated_peak_ciphertext_bytes =
      plan.parameter_plan.report.estimated_ciphertext_bytes *
      std::max(fan_out, plan.estimated_batch_ciphertext_count);
  plan.estimated_total_key_material_bytes =
      plan.keyset_plan.estimated_total_key_bytes;
  plan.estimated_peak_working_set_bytes =
      plan.estimated_peak_ciphertext_bytes +
      plan.estimated_total_key_material_bytes +
      plan.parameter_plan.report.estimated_ciphertext_bytes;

  if (plan.recommended_mul_backend.find("aux_base") != std::string::npos &&
      plan.compiled_mul_backend != "aux_base") {
    plan.warnings.push_back(
        "The heuristic recommendation favors aux-base, but the current build "
        "is compiled with residue-transfer as the multiplication scheme.");
  }
  if (plan.recommended_mul_backend.find("residue_transfer") !=
          std::string::npos &&
      plan.compiled_mul_backend != "residue_transfer") {
    plan.warnings.push_back(
        "The heuristic recommendation favors residue-transfer, but the current "
        "build is compiled with aux-base as the multiplication scheme.");
  }
  if (plan.keyset_plan.estimated_galois_key_count > 8) {
    plan.warnings.push_back(
        "The workload requires a relatively large Galois key set; consider "
        "simplifying the rotation schedule or packing strategy.");
  }

  return plan;
}

}  // namespace crypto::bfv
