#ifndef BFV_MATH_RNS_TRANSFER_EXECUTOR_H
#define BFV_MATH_RNS_TRANSFER_EXECUTOR_H

#include <memory>
#include <vector>

#include "math/rns_transfer_plan.h"

namespace bfv {
namespace math {
namespace rns {
namespace internal {

TransferWorkset::ScalarTerms BuildScalarCarryTerms(
    const TransferKernelCache &transfer_kernel,
    const ScalingFactor &scaling_factor, const std::vector<uint64_t> &rests);

void WriteScalarProjectionRow(const std::shared_ptr<RnsContext> &to_ctx,
                              const TransferKernelCache &transfer_kernel,
                              const ScalingFactor &scaling_factor,
                              const TransferWorkset::ScalarTerms &state,
                              const std::vector<uint64_t> &rests,
                              std::vector<uint64_t> &out,
                              size_t starting_index);

TransferWorkset::BatchWorkset BuildBatchCarryWorkset(
    const std::shared_ptr<RnsContext> &from_ctx,
    const TransferKernelCache &transfer_kernel,
    const ScalingFactor &scaling_factor,
    const std::vector<const uint64_t *> &input_moduli_ptrs,
    const std::vector<uint64_t *> &output_moduli_ptrs, ArenaHandle pool);

void WriteBatchProjectionWithoutCompensation(
    const std::shared_ptr<RnsContext> &to_ctx,
    const TransferKernelCache &transfer_kernel,
    const TransferWorkset::BatchWorkset &scratch, size_t count,
    size_t starting_index);

void WriteBatchProjectionWithCompensation(
    const std::shared_ptr<RnsContext> &to_ctx,
    const TransferKernelCache &transfer_kernel,
    const ScalingFactor &scaling_factor,
    const TransferWorkset::BatchWorkset &scratch, size_t count,
    size_t starting_index);

}  // namespace internal
}  // namespace rns
}  // namespace math
}  // namespace bfv

#endif  // BFV_MATH_RNS_TRANSFER_EXECUTOR_H
