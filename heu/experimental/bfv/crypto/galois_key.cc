#include "crypto/galois_key.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <random>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/secret_key.h"
#include "crypto/serialization/msgpack_adaptors.h"
#include "math/context.h"
#include "math/context_transfer.h"
#include "math/modulus.h"
#include "math/ntt_harvey.h"
#include "math/poly.h"
#include "math/representation.h"
#include "math/substitution_exponent.h"

namespace crypto {
namespace bfv {

namespace {
using Clock = std::chrono::steady_clock;

inline bool heu_galois_profile_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_GALOIS_PROFILE");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline int64_t micros_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
      .count();
}

void FusedInverseLazyAddFirst(::bfv::math::rq::Poly &delta0_ntt,
                              ::bfv::math::rq::Poly &delta1_ntt,
                              const ::bfv::math::rq::Poly &target0_power) {
  auto ctx = delta0_ntt.ctx();
  const size_t degree = ctx->degree();
  const auto &ops = ctx->ops();
  const auto &q_ops = ctx->q();

  for (size_t mod_idx = 0; mod_idx < q_ops.size(); ++mod_idx) {
    uint64_t *d0 = delta0_ntt.data(mod_idx);
    uint64_t *d1 = delta1_ntt.data(mod_idx);
    const uint64_t *t0 = target0_power.data(mod_idx);
    const auto *tables = ops[mod_idx].GetNTTTables();

    if (tables) {
      ::bfv::math::ntt::HarveyNTT::InverseHarveyNtt2(d0, d1, *tables);
      q_ops[mod_idx].AddVec(d0, t0, degree);
    } else {
      ops[mod_idx].BackwardInPlace(d0);
      ops[mod_idx].BackwardInPlace(d1);
      q_ops[mod_idx].AddVec(d0, t0, degree);
    }
  }

  delta0_ntt.override_representation(
      ::bfv::math::rq::Representation::PowerBasis);
  delta1_ntt.override_representation(
      ::bfv::math::rq::Representation::PowerBasis);
}

void ApplyAutomorphismInto(
    const ::bfv::math::rq::Poly &input_poly,
    const ::bfv::math::rq::SubstitutionExponent &automorphism_element,
    ::bfv::math::rq::Poly &output_poly) {
  using ::bfv::math::rq::Representation;

  if (!output_poly.ctx() || output_poly.ctx() != input_poly.ctx() ||
      output_poly.representation() != input_poly.representation()) {
    output_poly = ::bfv::math::rq::Poly::uninitialized(
        input_poly.ctx(), input_poly.representation());
  } else {
    output_poly.override_representation(input_poly.representation());
  }

  if (input_poly.allows_variable_time_computations()) {
    output_poly.allow_variable_time_computations();
  } else {
    output_poly.disallow_variable_time_computations();
  }

  const auto representation = input_poly.representation();
  const size_t degree = input_poly.ctx()->degree();
  const size_t num_moduli = input_poly.ctx()->q().size();

  if (representation == Representation::Ntt ||
      representation == Representation::NttShoup) {
    const auto &bit_reversed_powers = automorphism_element.power_bitrev();
    for (size_t mod_idx = 0; mod_idx < num_moduli; ++mod_idx) {
      const uint64_t *input_coeffs = input_poly.data(mod_idx);
      uint64_t *output_coeffs = output_poly.data(mod_idx);
      for (size_t j = 0; j < degree; ++j) {
        output_coeffs[j] = input_coeffs[bit_reversed_powers[j]];
      }
    }

    if (representation == Representation::NttShoup) {
      for (size_t mod_idx = 0; mod_idx < num_moduli; ++mod_idx) {
        const uint64_t *input_shoup_coeffs = input_poly.data_shoup(mod_idx);
        uint64_t *output_shoup_coeffs = output_poly.data_shoup(mod_idx);
        for (size_t j = 0; j < degree; ++j) {
          output_shoup_coeffs[j] = input_shoup_coeffs[bit_reversed_powers[j]];
        }
      }
    }
    return;
  }

  // Power-basis substitute with sign flip when crossing X^N = -1.
  const size_t mask = degree - 1;
  const size_t automorphism_stride = automorphism_element.exponent();
  for (size_t mod_idx = 0; mod_idx < num_moduli; ++mod_idx) {
    const auto &modulus = input_poly.ctx()->q()[mod_idx];
    const uint64_t modulus_value = modulus.P();
    const uint64_t *input_coeffs = input_poly.data(mod_idx);
    uint64_t *output_coeffs = output_poly.data(mod_idx);
    size_t power_index = 0;
    for (size_t j = 0; j < degree; ++j, power_index += automorphism_stride) {
      const size_t destination_index = power_index & mask;
      uint64_t value = input_coeffs[j];
      if (power_index & degree) {
        const uint64_t non_zero = static_cast<uint64_t>(value != 0);
        value = (modulus_value - value) & static_cast<uint64_t>(-non_zero);
      }
      output_coeffs[destination_index] = value;
    }
  }
}
}  // namespace

class GaloisKey::Impl {
 public:
  std::unique_ptr<KeySwitchingKey> switch_key_;
  size_t automorphism_exponent_;
  std::shared_ptr<::bfv::math::rq::SubstitutionExponent> automorphism_map_;

  Impl()
      : switch_key_(nullptr),
        automorphism_exponent_(0),
        automorphism_map_(nullptr) {}

  Impl(KeySwitchingKey key_switching_key, size_t exp,
       std::shared_ptr<::bfv::math::rq::SubstitutionExponent>
           automorphism_element)
      : switch_key_(
            std::make_unique<KeySwitchingKey>(std::move(key_switching_key))),
        automorphism_exponent_(exp),
        automorphism_map_(std::move(automorphism_element)) {}
};

GaloisKey::~GaloisKey() = default;

GaloisKey::GaloisKey(const GaloisKey &other) {
  if (other.impl_ && other.impl_->switch_key_ &&
      other.impl_->automorphism_map_) {
    impl_ = std::make_unique<Impl>();
    impl_->switch_key_ =
        std::make_unique<KeySwitchingKey>(*other.impl_->switch_key_);
    impl_->automorphism_exponent_ = other.impl_->automorphism_exponent_;
    impl_->automorphism_map_ = other.impl_->automorphism_map_;
  }
}

GaloisKey &GaloisKey::operator=(const GaloisKey &other) {
  if (this != &other) {
    if (other.impl_ && other.impl_->switch_key_ &&
        other.impl_->automorphism_map_) {
      if (!impl_) {
        impl_ = std::make_unique<Impl>();
      }
      impl_->switch_key_ =
          std::make_unique<KeySwitchingKey>(*other.impl_->switch_key_);
      impl_->automorphism_exponent_ = other.impl_->automorphism_exponent_;
      impl_->automorphism_map_ = other.impl_->automorphism_map_;
    } else {
      impl_.reset();
    }
  }
  return *this;
}

GaloisKey::GaloisKey(GaloisKey &&other) noexcept = default;
GaloisKey &GaloisKey::operator=(GaloisKey &&other) noexcept = default;

GaloisKey::GaloisKey(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

GaloisKey GaloisKey::create(const SecretKey &secret_key, size_t exponent,
                            size_t ciphertext_level, size_t galois_key_level,
                            std::mt19937_64 &rng) {
  if (secret_key.empty()) {
    throw ParameterException("Secret key is empty");
  }

  try {
    auto params = secret_key.parameters();

    // Validate level relationship (galois_key_level should be <=
    // ciphertext_level)
    if (galois_key_level > ciphertext_level) {
      throw ParameterException(
          "Galois key level cannot be greater than ciphertext level");
    }

    // Load contexts for key generation and ciphertext usage.
    auto galois_key_ctx = params->ctx_at_level(galois_key_level);

    auto ciphertext_ctx = params->ctx_at_level(ciphertext_level);

    // Use cached substitution exponent from context.
    auto automorphism_element =
        ciphertext_ctx->get_substitution_exponent(exponent);

    auto level_transfer = ::bfv::math::rq::ContextTransfer::create(
        ciphertext_ctx, galois_key_ctx);

    auto lifted_substituted_secret =
        secret_key
            .cached_substituted_ntt_key_at(ciphertext_ctx,
                                           *automorphism_element)
            .remap_to_context(*level_transfer);

    auto key_switching_key =
        KeySwitchingKey::create(secret_key, lifted_substituted_secret,
                                ciphertext_level, galois_key_level, rng);

    // Create implementation
    auto impl = std::make_unique<Impl>(std::move(key_switching_key), exponent,
                                       std::move(automorphism_element));

    return GaloisKey(std::move(impl));

  } catch (const std::exception &e) {
    throw MathException("Failed to generate Galois key: " +
                        std::string(e.what()));
  }
}

Ciphertext GaloisKey::apply(const Ciphertext &ciphertext) const {
  if (!impl_ || !impl_->switch_key_ || !impl_->automorphism_map_) {
    throw ParameterException("Galois key is not initialized");
  }

  if (ciphertext.parameters() != parameters()) {
    throw ParameterException("Incompatible BFV parameters");
  }

  if (ciphertext.polynomials().size() != 2) {
    throw ParameterException("Ciphertext must have exactly 2 polynomials");
  }

  try {
    const bool profile_enabled = heu_galois_profile_enabled();
    const auto total_begin_time =
        profile_enabled ? Clock::now() : Clock::time_point{};
    int64_t component1_substitute_us = 0;
    int64_t key_switch_stage_us = 0;
    int64_t mod_switch_stage_us = 0;
    int64_t component0_substitute_us = 0;
    int64_t representation_sync_us = 0;
    int64_t component_merge_us = 0;

    const auto &ciphertext_polynomials = ciphertext.polynomials();
    const auto target_repr = ciphertext_polynomials[0].representation();

    // Apply automorphism to the second component before key switching.
    const auto component1_substitute_begin =
        profile_enabled ? Clock::now() : Clock::time_point{};
    thread_local ::bfv::math::rq::Poly substituted_component1_buffer;
    ApplyAutomorphismInto(ciphertext_polynomials[1], *impl_->automorphism_map_,
                          substituted_component1_buffer);
    auto &substituted_component1 = substituted_component1_buffer;
    if (substituted_component1.representation() !=
        ::bfv::math::rq::Representation::PowerBasis) {
      substituted_component1.change_representation(
          ::bfv::math::rq::Representation::PowerBasis);
    }
    if (profile_enabled) {
      component1_substitute_us =
          micros_between(component1_substitute_begin, Clock::now());
    }

    auto key_switch_context = impl_->switch_key_->parameters()->ctx_at_level(
        impl_->switch_key_->ksk_level());
    const bool same_context_output =
        key_switch_context == ciphertext_polynomials[0].ctx();
    const bool can_fuse_power_output =
        same_context_output &&
        target_repr == ::bfv::math::rq::Representation::PowerBasis;
    const bool can_keep_ntt_output =
        same_context_output &&
        target_repr == ::bfv::math::rq::Representation::Ntt;
    const auto key_switch_stage_begin =
        profile_enabled ? Clock::now() : Clock::time_point{};
    thread_local ::bfv::math::rq::Poly switched_component0_buffer;
    thread_local ::bfv::math::rq::Poly switched_component1_buffer;
    auto &switched_component0 = switched_component0_buffer;
    auto &switched_component1 = switched_component1_buffer;
    impl_->switch_key_->apply_key_switch_into(
        substituted_component1, switched_component0, switched_component1,
        (can_fuse_power_output || can_keep_ntt_output)
            ? ::bfv::math::rq::Representation::Ntt
            : ::bfv::math::rq::Representation::PowerBasis);
    if (profile_enabled) {
      key_switch_stage_us =
          micros_between(key_switch_stage_begin, Clock::now());
    }

    // Align key-switched components to ciphertext context when needed.
    if (!same_context_output &&
        switched_component0.ctx() != ciphertext_polynomials[0].ctx()) {
      const auto mod_switch_stage_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      switched_component0.drop_to_context(ciphertext_polynomials[0].ctx());
      switched_component1.drop_to_context(ciphertext_polynomials[1].ctx());
      if (profile_enabled) {
        mod_switch_stage_us =
            micros_between(mod_switch_stage_begin, Clock::now());
      }
    }

    const auto component0_substitute_begin =
        profile_enabled ? Clock::now() : Clock::time_point{};
    thread_local ::bfv::math::rq::Poly substituted_component0_buffer;
    ApplyAutomorphismInto(ciphertext_polynomials[0], *impl_->automorphism_map_,
                          substituted_component0_buffer);
    auto &substituted_component0 = substituted_component0_buffer;
    if (substituted_component0.representation() != target_repr) {
      substituted_component0.change_representation(target_repr);
    }
    if (profile_enabled) {
      component0_substitute_us =
          micros_between(component0_substitute_begin, Clock::now());
    }
    if (!same_context_output &&
        target_repr != ::bfv::math::rq::Representation::PowerBasis) {
      const auto representation_sync_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      switched_component0.change_representation(target_repr);
      switched_component1.change_representation(target_repr);
      if (profile_enabled) {
        representation_sync_us =
            micros_between(representation_sync_begin, Clock::now());
      }
    }

    const auto component_merge_begin =
        profile_enabled ? Clock::now() : Clock::time_point{};
    if (can_fuse_power_output) {
      FusedInverseLazyAddFirst(switched_component0, switched_component1,
                               substituted_component0);
    } else {
      switched_component0 += substituted_component0;
    }
    if (profile_enabled) {
      component_merge_us = micros_between(component_merge_begin, Clock::now());
      const auto total_us = micros_between(total_begin_time, Clock::now());
      std::cerr << "[HEU_GALOIS_PROFILE]"
                << " component1_substitute_us=" << component1_substitute_us
                << " key_switch_stage_us=" << key_switch_stage_us
                << " mod_switch_stage_us=" << mod_switch_stage_us
                << " component0_substitute_us=" << component0_substitute_us
                << " representation_sync_us=" << representation_sync_us
                << " component_merge_us=" << component_merge_us
                << " total_us=" << total_us << '\n';
    }

    std::vector<::bfv::math::rq::Poly> result_polys;
    result_polys.reserve(2);
    result_polys.push_back(switched_component0);
    result_polys.push_back(switched_component1);

    // Use the ciphertext_level from the key switching key
    size_t result_level = impl_->switch_key_->ciphertext_level();
    return Ciphertext::from_polynomials_with_level(
        std::move(result_polys), ciphertext.parameters(), result_level);

  } catch (const std::exception &e) {
    throw MathException("Failed to apply Galois key: " + std::string(e.what()));
  }
}

std::shared_ptr<BfvParameters> GaloisKey::parameters() const {
  return (impl_ && impl_->switch_key_) ? impl_->switch_key_->parameters()
                                       : nullptr;
}

size_t GaloisKey::exponent() const {
  return (impl_ && impl_->automorphism_map_)
             ? impl_->automorphism_map_->exponent()
             : 0;
}

size_t GaloisKey::ciphertext_level() const {
  return (impl_ && impl_->switch_key_) ? impl_->switch_key_->ciphertext_level()
                                       : 0;
}

size_t GaloisKey::galois_key_level() const {
  return (impl_ && impl_->switch_key_) ? impl_->switch_key_->ksk_level() : 0;
}

bool GaloisKey::empty() const {
  return !impl_ || !impl_->switch_key_ || !impl_->automorphism_map_ ||
         impl_->switch_key_->empty();
}

const KeySwitchingKey &GaloisKey::key_switching_key() const {
  if (!impl_ || !impl_->switch_key_) {
    throw ParameterException("Galois key is not initialized");
  }
  return *impl_->switch_key_;
}

bool GaloisKey::operator==(const GaloisKey &other) const {
  if (!impl_ && !other.impl_) return true;
  if (!impl_ || !other.impl_) return false;
  if (!impl_->switch_key_ && !other.impl_->switch_key_)
    return impl_->automorphism_map_->exponent() ==
           other.impl_->automorphism_map_->exponent();
  if (!impl_->switch_key_ || !other.impl_->switch_key_) return false;
  if (!impl_->automorphism_map_ && !other.impl_->automorphism_map_)
    return *impl_->switch_key_ == *other.impl_->switch_key_;
  if (!impl_->automorphism_map_ || !other.impl_->automorphism_map_) {
    return false;
  }

  return *impl_->switch_key_ == *other.impl_->switch_key_ &&
         impl_->automorphism_map_->exponent() ==
             other.impl_->automorphism_map_->exponent();
}

bool GaloisKey::operator!=(const GaloisKey &other) const {
  return !(*this == other);
}

yacl::Buffer GaloisKey::Serialize() const {
  if (!impl_ || !impl_->switch_key_ || !impl_->automorphism_map_) {
    throw SerializationException("GaloisKey is not initialized");
  }

  auto serialized_ksk = impl_->switch_key_->Serialize();
  GaloisKeyData data;
  data.exponent = impl_->automorphism_map_->exponent();
  data.key_switching_key.assign(
      serialized_ksk.data<uint8_t>(),
      serialized_ksk.data<uint8_t>() + serialized_ksk.size());
  return MsgpackSerializer::Serialize(data);
}

void GaloisKey::Deserialize(yacl::ByteContainerView in,
                            std::shared_ptr<BfvParameters> params) {
  *this = from_bytes(in, std::move(params));
}

GaloisKey GaloisKey::from_bytes(yacl::ByteContainerView bytes,
                                std::shared_ptr<BfvParameters> params) {
  if (!params) {
    throw SerializationException("Parameters are required for GaloisKey");
  }

  try {
    auto data = MsgpackSerializer::Deserialize<GaloisKeyData>(bytes);
    auto key_switching_key = KeySwitchingKey::from_bytes(
        yacl::ByteContainerView(data.key_switching_key.data(),
                                data.key_switching_key.size()),
        params);
    return from_components(std::move(key_switching_key), data.exponent,
                           std::move(params));
  } catch (const SerializationException &) {
    throw;
  } catch (const std::exception &e) {
    throw SerializationException("Failed to deserialize GaloisKey: " +
                                 std::string(e.what()));
  }
}

GaloisKey GaloisKey::from_components(KeySwitchingKey key_switching_key,
                                     size_t exponent,
                                     std::shared_ptr<BfvParameters> params) {
  auto key_context = params->ctx_at_level(key_switching_key.ciphertext_level());
  auto automorphism_element = key_context->get_substitution_exponent(exponent);

  auto impl = std::make_unique<Impl>(std::move(key_switching_key), exponent,
                                     std::move(automorphism_element));
  return GaloisKey(std::move(impl));
}

}  // namespace bfv
}  // namespace crypto
