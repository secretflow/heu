#include "math/ntt_tables.h"

#include <memory>

namespace bfv {
namespace math {
namespace ntt {

struct NTTTables::Impl {
  zq::Modulus modulus_;
  size_t coeff_count_;

  // Root powers stored in bit-reversed order for forward NTT
  std::vector<zq::MultiplyUIntModOperand> root_powers_;

  // Inverse root powers stored in scrambled order for inverse NTT
  std::vector<zq::MultiplyUIntModOperand> inv_root_powers_;

  // Inverse of degree modulo the prime, stored as MultiplyUIntModOperand
  zq::MultiplyUIntModOperand inv_degree_modulo_;

  Impl(const zq::Modulus &modulus, size_t coeff_count)
      : modulus_(modulus), coeff_count_(coeff_count) {}
};

NTTTables::NTTTables(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

NTTTables::NTTTables(const NTTTables &other)
    : impl_(std::make_unique<Impl>(*other.impl_)) {}

NTTTables::NTTTables(NTTTables &&other) noexcept
    : impl_(std::move(other.impl_)) {}

NTTTables::~NTTTables() = default;

std::optional<NTTTables> NTTTables::Create(const zq::Modulus &modulus,
                                           size_t coeff_count) {
  auto layout = internal::BuildNttLayout(modulus, coeff_count);
  if (!layout.has_value()) {
    return std::nullopt;
  }

  auto impl = std::make_unique<Impl>(modulus, coeff_count);

  impl->root_powers_ = std::move(layout->forward_root_layout);
  impl->inv_root_powers_ = std::move(layout->inverse_root_layout);
  impl->inv_degree_modulo_ = layout->inverse_degree;

  return NTTTables(std::move(impl));
}

const zq::Modulus &NTTTables::GetModulus() const { return impl_->modulus_; }

size_t NTTTables::GetCoeffCount() const { return impl_->coeff_count_; }

const std::vector<zq::MultiplyUIntModOperand> &NTTTables::GetRootPowers()
    const {
  return impl_->root_powers_;
}

const std::vector<zq::MultiplyUIntModOperand> &NTTTables::GetInvRootPowers()
    const {
  return impl_->inv_root_powers_;
}

const zq::MultiplyUIntModOperand &NTTTables::GetInvDegreeModulo() const {
  return impl_->inv_degree_modulo_;
}

uint64_t NTTTables::FindPrimitiveRoot(size_t coeff_count,
                                      const zq::Modulus &modulus) {
  return internal::FindPrimitiveNthRoot(coeff_count, modulus);
}

bool NTTTables::IsPrimitiveRoot(uint64_t root, size_t coeff_count,
                                const zq::Modulus &modulus) {
  return internal::MatchesPrimitiveRootOrder(root, coeff_count, modulus);
}

size_t NTTTables::ReverseBits(size_t value, size_t bit_count) {
  return internal::ReverseBitOrder(value, bit_count);
}

}  // namespace ntt
}  // namespace math
}  // namespace bfv
