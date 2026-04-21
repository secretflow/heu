#include "math/context_transfer.h"

#include <stdexcept>

#include "math/basis_mapper.h"
#include "math/context.h"
#include "math/poly.h"
#include "math/scaling_factor.h"

namespace bfv::math::rq {

/**
 * @brief Implementation class for ContextTransfer using PIMPL pattern.
 */
class ContextTransfer::Impl {
 public:
  std::shared_ptr<const Context> source_ctx;
  std::shared_ptr<const Context> target_ctx;
  ::bfv::math::rns::ScalingFactor transfer_factor;
  std::unique_ptr<BasisMapper> transfer_mapper;

  /**
   * @brief Constructor for ContextTransfer::Impl.
   */
  Impl(std::shared_ptr<const Context> from_ctx,
       std::shared_ptr<const Context> to_ctx)
      : source_ctx(from_ctx),
        target_ctx(to_ctx),
        transfer_factor(to_ctx->modulus(), from_ctx->modulus()) {
    transfer_mapper = BasisMapper::create(std::move(from_ctx),
                                          std::move(to_ctx), transfer_factor);
  }
};

std::unique_ptr<ContextTransfer> ContextTransfer::create(
    std::shared_ptr<const Context> from, std::shared_ptr<const Context> to) {
  auto impl = std::make_unique<Impl>(std::move(from), std::move(to));
  return std::unique_ptr<ContextTransfer>(new ContextTransfer(std::move(impl)));
}

ContextTransfer::ContextTransfer(std::unique_ptr<Impl> impl)
    : pimpl_(std::move(impl)) {}

ContextTransfer::~ContextTransfer() = default;

ContextTransfer::ContextTransfer(ContextTransfer &&) noexcept = default;
ContextTransfer &ContextTransfer::operator=(ContextTransfer &&) noexcept =
    default;

Poly ContextTransfer::apply(const Poly &poly) const {
  if (*poly.ctx() != *pimpl_->source_ctx) {
    throw std::runtime_error(
        "The input polynomial does not have the correct transfer source "
        "context");
  }
  return pimpl_->transfer_mapper->map(poly);
}

bool ContextTransfer::operator==(const ContextTransfer &other) const {
  return pimpl_->source_ctx == other.pimpl_->source_ctx &&
         pimpl_->target_ctx == other.pimpl_->target_ctx &&
         *pimpl_->transfer_mapper == *other.pimpl_->transfer_mapper;
}

bool ContextTransfer::operator!=(const ContextTransfer &other) const {
  return !(*this == other);
}

}  // namespace bfv::math::rq
