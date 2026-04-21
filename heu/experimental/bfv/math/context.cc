#include "math/context.h"

#include <algorithm>
#include <mutex>
#include <unordered_map>

#include "math/context_layout.h"
#include "math/exceptions.h"
#include "math/substitution_exponent.h"

namespace bfv::math::rq {

/**
 * @brief PIMPL implementation class for Context.
 */
class Context::Impl {
 public:
  using RingLayout = internal::RingLayoutData;
  using TransformLayout = internal::TransformLayoutData;
  using LevelSwitchLayout = internal::LevelSwitchLayoutData;

  struct ChainLayout {
    std::shared_ptr<Context> lower_level;
  };

  struct AutomorphismCache {
    mutable std::mutex mutex;
    mutable std::unordered_map<size_t, std::shared_ptr<SubstitutionExponent>>
        exponent_map;
  };

  RingLayout ring;
  TransformLayout transforms;
  LevelSwitchLayout level_switch;
  ChainLayout chain;
  AutomorphismCache automorphisms;

  Impl() = default;
  ~Impl() = default;

  // Disable copy
  Impl(const Impl &) = delete;
  Impl &operator=(const Impl &) = delete;

  // Enable move
  Impl(Impl &&) = default;
  Impl &operator=(Impl &&) = default;
};

Context::Context(std::unique_ptr<Impl> impl) : pimpl_(std::move(impl)) {}

Context::~Context() = default;

Context::Context(Context &&) noexcept = default;
Context &Context::operator=(Context &&) noexcept = default;

std::shared_ptr<Context> Context::create(const std::vector<uint64_t> &moduli,
                                         size_t degree) {
  // Validate degree is power of 2 and >= 8
  if (degree < 8 || (degree & (degree - 1)) != 0) {
    throw DefaultException(
        "Context degree must be a power of two and at least 8");
  }

  auto impl = std::make_unique<Impl>();
  impl->ring = internal::BuildRingLayout(moduli, degree);
  impl->transforms = internal::BuildTransformLayout(impl->ring);
  impl->level_switch = internal::BuildLevelSwitchLayout(impl->ring);
  impl->chain.lower_level = internal::BuildLowerLevelChain(moduli, degree);

  return std::shared_ptr<Context>(new Context(std::move(impl)));
}

std::shared_ptr<Context> Context::create_arc(
    const std::vector<uint64_t> &moduli, size_t degree) {
  return create(moduli, degree);
}

const ::bfv::math::rns::BigUint &Context::modulus() const {
  return pimpl_->ring.residue_basis->modulus();
}

const std::vector<uint64_t> &Context::moduli() const {
  return pimpl_->ring.basis_moduli;
}

const std::vector<::bfv::math::zq::Modulus> &Context::moduli_operators() const {
  return pimpl_->ring.residue_operators;
}

size_t Context::degree() const { return pimpl_->ring.polynomial_degree; }

size_t Context::niterations_to(std::shared_ptr<const Context> context) const {
  // Fast path: pointer equality
  if (context.get() == this) {
    return 0;
  }
  // Content equality
  if (*this == *context) {
    return 0;
  }

  size_t niterations = 0;
  auto current_ctx = shared_from_this();

  while (current_ctx->pimpl_->chain.lower_level) {
    niterations++;
    current_ctx = current_ctx->pimpl_->chain.lower_level;

    if (*current_ctx == *context) {
      return niterations;
    }
  }

  throw InvalidContextException();
}

std::shared_ptr<Context> Context::context_at_level(size_t level) const {
  if (level >= pimpl_->ring.basis_moduli.size()) {
    throw DefaultException("Requested level is outside the context chain");
  }

  auto current_ctx = std::const_pointer_cast<Context>(shared_from_this());
  for (size_t i = 0; i < level; ++i) {
    current_ctx = current_ctx->pimpl_->chain.lower_level;
  }

  return current_ctx;
}

std::shared_ptr<const Context> Context::next_context() const {
  return pimpl_->chain.lower_level;
}

const std::vector<::bfv::math::zq::Modulus> &Context::q() const {
  return pimpl_->ring.residue_operators;
}

std::shared_ptr<const ::bfv::math::rns::RnsContext> Context::rns() const {
  return pimpl_->ring.residue_basis;
}

const std::vector<::bfv::math::ntt::NttOperator> &Context::ops() const {
  return pimpl_->transforms.transform_operators;
}

const std::vector<size_t> &Context::bitrev() const {
  return pimpl_->transforms.slot_permutation;
}

const std::vector<uint64_t> &Context::inv_last_qi_mod_qj() const {
  return pimpl_->level_switch.tail_to_head_inverse;
}

const std::vector<uint64_t> &Context::inv_last_qi_mod_qj_shoup() const {
  return pimpl_->level_switch.tail_to_head_inverse_shoup;
}

bool Context::operator==(const Context &other) const {
  if (this == &other) return true;
  return pimpl_->ring.basis_moduli == other.pimpl_->ring.basis_moduli &&
         pimpl_->ring.polynomial_degree == other.pimpl_->ring.polynomial_degree;
}

bool Context::operator!=(const Context &other) const {
  return !(*this == other);
}

std::shared_ptr<SubstitutionExponent> Context::get_substitution_exponent(
    size_t exponent) const {
  std::lock_guard<std::mutex> lock(pimpl_->automorphisms.mutex);
  auto it = pimpl_->automorphisms.exponent_map.find(exponent);
  if (it != pimpl_->automorphisms.exponent_map.end()) {
    return it->second;
  }

  auto sub_exp = SubstitutionExponent::create(
      std::const_pointer_cast<const Context>(shared_from_this()), exponent);
  pimpl_->automorphisms.exponent_map[exponent] = sub_exp;
  return sub_exp;
}

}  // namespace bfv::math::rq
