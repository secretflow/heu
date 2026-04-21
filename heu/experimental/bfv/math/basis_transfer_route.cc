#include "math/basis_transfer_route.h"

#include <algorithm>
#include <stdexcept>

#include "math/residue_transfer_engine.h"

namespace bfv::math::rq::internal {

class BasisTransferRoute::TransferBackend {
 public:
  TransferBackend(std::shared_ptr<const Context> source_ctx,
                  std::shared_ptr<const Context> target_ctx,
                  const ::bfv::math::rns::ScalingFactor &factor)
      : route_backend_(std::const_pointer_cast<::bfv::math::rns::RnsContext>(
                           source_ctx->rns()),
                       std::const_pointer_cast<::bfv::math::rns::RnsContext>(
                           target_ctx->rns()),
                       factor) {}

  bool uses_aux_base_multiply_path() const {
    return route_backend_.uses_aux_base_multiply_path();
  }

  void scale_batch(const std::vector<const uint64_t *> &input_moduli_ptrs,
                   const std::vector<uint64_t *> &output_moduli_ptrs,
                   size_t count, ::bfv::util::ArenaHandle pool,
                   size_t prefix_passthrough_count) const {
    route_backend_.scale_batch(input_moduli_ptrs, output_moduli_ptrs, count,
                               prefix_passthrough_count, pool);
  }

 private:
  ::bfv::math::rns::ResidueTransferEngine route_backend_;
};

BasisTransferRoute::BasisTransferRoute(
    std::shared_ptr<const Context> source_ctx,
    std::shared_ptr<const Context> target_ctx,
    const ::bfv::math::rns::ScalingFactor &factor) {
  if (source_ctx->degree() != target_ctx->degree()) {
    throw std::runtime_error("Incompatible degrees");
  }

  if (factor.is_one()) {
    const auto &source_moduli = source_ctx->moduli();
    const auto &target_moduli = target_ctx->moduli();
    for (size_t i = 0; i < std::min(source_moduli.size(), target_moduli.size());
         ++i) {
      if (source_moduli[i] == target_moduli[i]) {
        ++prefix_passthrough_count_;
      } else {
        break;
      }
    }
  }

  if (prefix_passthrough_count_ < target_ctx->moduli().size()) {
    transfer_backend_ = std::make_unique<TransferBackend>(
        std::move(source_ctx), std::move(target_ctx), factor);
  }
}

BasisTransferRoute::~BasisTransferRoute() = default;
BasisTransferRoute::BasisTransferRoute(BasisTransferRoute &&) noexcept =
    default;
BasisTransferRoute &BasisTransferRoute::operator=(
    BasisTransferRoute &&) noexcept = default;

bool BasisTransferRoute::uses_aux_base_multiply_path() const {
  return transfer_backend_ && transfer_backend_->uses_aux_base_multiply_path();
}

void BasisTransferRoute::scale_batch(
    const std::vector<const uint64_t *> &input_moduli_ptrs,
    const std::vector<uint64_t *> &output_moduli_ptrs, size_t count,
    ::bfv::util::ArenaHandle pool) const {
  if (!transfer_backend_) {
    return;
  }
  transfer_backend_->scale_batch(input_moduli_ptrs, output_moduli_ptrs, count,
                                 pool, prefix_passthrough_count_);
}

}  // namespace bfv::math::rq::internal
