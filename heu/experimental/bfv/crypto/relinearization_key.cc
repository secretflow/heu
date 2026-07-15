#include "crypto/relinearization_key.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/key_switching_key.h"
#include "crypto/secret_key.h"
#include "crypto/serialization/msgpack_adaptors.h"
#include "math/context.h"
#include "math/context_transfer.h"
#include "math/modulus.h"
#include "math/ntt_harvey.h"
#include "math/poly.h"
#include "math/representation.h"
#include "math/sample_vec_cbd.h"
#include "util/profiler.h"

namespace crypto {
namespace bfv {

namespace {
using Clock = std::chrono::steady_clock;

inline bool heu_relin_profile_enabled() {
  static const bool enabled = [] {
    const char *env = std::getenv("HEU_BFV_MUL_PROFILE");
    return env && env[0] != '\0' && env[0] != '0';
  }();
  return enabled;
}

inline int64_t micros_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
      .count();
}

void FusedInverseLazyAddPair(::bfv::math::rq::Poly &delta0_ntt,
                             ::bfv::math::rq::Poly &delta1_ntt,
                             ::bfv::math::rq::Poly &target0_power,
                             ::bfv::math::rq::Poly &target1_power) {
  auto ctx = delta0_ntt.ctx();
  const size_t degree = ctx->degree();
  const auto &ops = ctx->ops();
  const auto &q_ops = ctx->q();

  for (size_t mod_idx = 0; mod_idx < q_ops.size(); ++mod_idx) {
    uint64_t *d0 = delta0_ntt.data(mod_idx);
    uint64_t *d1 = delta1_ntt.data(mod_idx);
    uint64_t *t0 = target0_power.data(mod_idx);
    uint64_t *t1 = target1_power.data(mod_idx);
    const auto *tables = ops[mod_idx].GetNTTTables();

    if (tables) {
      ::bfv::math::ntt::HarveyNTT::InverseHarveyNtt2(d0, d1, *tables);
      q_ops[mod_idx].AddVec(d0, t0, degree);
      q_ops[mod_idx].AddVec(d1, t1, degree);
    } else {
      ops[mod_idx].BackwardInPlace(d0);
      ops[mod_idx].BackwardInPlace(d1);
      q_ops[mod_idx].AddVec(d0, t0, degree);
      q_ops[mod_idx].AddVec(d1, t1, degree);
    }
  }
}

}  // namespace

// RelinearizationKey::Impl - PIMPL implementation
class RelinearizationKey::Impl {
 public:
  KeySwitchingKey switching_key;  // The underlying key switching key

  // Constructor from key switching key
  explicit Impl(KeySwitchingKey key_switching_key)
      : switching_key(std::move(key_switching_key)) {}
};

// RelinearizationKey implementation
RelinearizationKey::~RelinearizationKey() = default;

RelinearizationKey::RelinearizationKey(const RelinearizationKey &other)
    : impl_(std::make_unique<Impl>(*other.impl_)) {}

RelinearizationKey &RelinearizationKey::operator=(
    const RelinearizationKey &other) {
  if (this != &other) {
    *impl_ = *other.impl_;
  }
  return *this;
}

RelinearizationKey::RelinearizationKey(RelinearizationKey &&other) noexcept =
    default;
RelinearizationKey &RelinearizationKey::operator=(
    RelinearizationKey &&other) noexcept = default;

RelinearizationKey::RelinearizationKey(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

RelinearizationKey RelinearizationKey::from_secret_key(
    const SecretKey &secret_key, std::mt19937_64 &rng) {
  return from_secret_key_leveled_internal(secret_key, 0, 0, rng);
}

RelinearizationKey RelinearizationKey::from_secret_key_leveled(
    const SecretKey &secret_key, size_t ciphertext_level, size_t key_level,
    std::mt19937_64 &rng) {
  return from_secret_key_leveled_internal(secret_key, ciphertext_level,
                                          key_level, rng);
}

RelinearizationKey RelinearizationKey::from_secret_key_leveled_internal(
    const SecretKey &secret_key, size_t ciphertext_level, size_t key_level,
    std::mt19937_64 &rng) {
  PROFILE_BLOCK("RK: from_secret_key");
  if (secret_key.empty()) {
    throw ParameterException("Secret key is empty");
  }

  try {
    auto params = secret_key.parameters();

    auto ctx_relin_key = params->ctx_at_level(key_level);
    auto ctx_ciphertext = params->ctx_at_level(ciphertext_level);

    if (ctx_relin_key->moduli().size() == 1) {
      throw ParameterException("These parameters do not support key switching");
    }

    auto lift_transfer =
        ::bfv::math::rq::ContextTransfer::create(ctx_ciphertext, ctx_relin_key);
    auto s2_switched_up = secret_key.cached_square_ntt_key_at(ctx_ciphertext)
                              .remap_to_context(*lift_transfer);

    auto ksk = KeySwitchingKey::create(secret_key, s2_switched_up,
                                       ciphertext_level, key_level, rng);

    // Create implementation
    auto impl = std::make_unique<Impl>(std::move(ksk));

    return RelinearizationKey(std::move(impl));

  } catch (const std::exception &e) {
    throw MathException("Failed to generate relinearization key: " +
                        std::string(e.what()));
  }
}

void RelinearizationKey::relinearize(Ciphertext &ciphertext) const {
  const bool profile_enabled = heu_relin_profile_enabled();
  const auto total_begin = profile_enabled ? Clock::now() : Clock::time_point{};
  int64_t t_key_switch_us = 0;
  int64_t t_modswitch_us = 0;
  int64_t t_repr_us = 0;
  int64_t t_add_us = 0;
  int64_t t_truncate_us = 0;

  if (!impl_) {
    throw ParameterException("Relinearization key is not initialized");
  }

  const auto &ct_polys = ciphertext.polynomials();
  if (ct_polys.size() != 3) {
    throw ParameterException(
        "Only supports relinearization of ciphertext with 3 parts");
  }

  if (ciphertext.level() != impl_->switching_key.ciphertext_level()) {
    throw ParameterException("Ciphertext has incorrect level");
  }

  try {
    const ::bfv::math::rq::Poly *c2_ptr = &ct_polys[2];
    ::bfv::math::rq::Poly c2_owned;
    const auto target_repr = ct_polys[0].representation();
    if (c2_ptr->representation() !=
        ::bfv::math::rq::Representation::PowerBasis) {
      c2_owned = *c2_ptr;
      c2_owned.change_representation(
          ::bfv::math::rq::Representation::PowerBasis);
      c2_ptr = &c2_owned;
    }

    const bool can_fuse_power_output =
        target_repr == ::bfv::math::rq::Representation::PowerBasis &&
        impl_->switching_key.ciphertext_level() ==
            impl_->switching_key.ksk_level();
    const auto key_switch_output_representation =
        can_fuse_power_output ? ::bfv::math::rq::Representation::Ntt
                              : ::bfv::math::rq::Representation::PowerBasis;

    const auto key_switch_begin =
        profile_enabled ? Clock::now() : Clock::time_point{};
    thread_local ::bfv::math::rq::Poly tl_c0_delta;
    thread_local ::bfv::math::rq::Poly tl_c1_delta;
    auto &c0_delta = tl_c0_delta;
    auto &c1_delta = tl_c1_delta;
    impl_->switching_key.apply_key_switch_into(
        *c2_ptr, c0_delta, c1_delta, key_switch_output_representation);
    if (profile_enabled) {
      t_key_switch_us = micros_between(key_switch_begin, Clock::now());
    }

    if (!can_fuse_power_output &&
        (c0_delta.representation() !=
             ::bfv::math::rq::Representation::PowerBasis ||
         c1_delta.representation() !=
             ::bfv::math::rq::Representation::PowerBasis)) {
      const auto repr_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      c0_delta.change_representation(
          ::bfv::math::rq::Representation::PowerBasis);
      c1_delta.change_representation(
          ::bfv::math::rq::Representation::PowerBasis);
      if (profile_enabled) {
        t_repr_us += micros_between(repr_begin, Clock::now());
      }
    }

    if (!can_fuse_power_output && c0_delta.ctx() != ct_polys[0].ctx()) {
      const auto modswitch_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      c0_delta.drop_to_context(ct_polys[0].ctx());
      c1_delta.drop_to_context(ct_polys[1].ctx());
      if (profile_enabled) {
        t_modswitch_us = micros_between(modswitch_begin, Clock::now());
      }
    }
    if (!can_fuse_power_output &&
        target_repr != ::bfv::math::rq::Representation::PowerBasis) {
      const auto repr_begin =
          profile_enabled ? Clock::now() : Clock::time_point{};
      c0_delta.change_representation(target_repr);
      c1_delta.change_representation(target_repr);
      if (profile_enabled) {
        t_repr_us = micros_between(repr_begin, Clock::now());
      }
    }

    const auto add_begin = profile_enabled ? Clock::now() : Clock::time_point{};
    if (can_fuse_power_output) {
      auto &target0 = ciphertext.mutable_component(0);
      auto &target1 = ciphertext.mutable_component(1);
      FusedInverseLazyAddPair(c0_delta, c1_delta, target0, target1);
    } else {
      ciphertext.add_to_component(0, c0_delta);
      ciphertext.add_to_component(1, c1_delta);
    }
    if (profile_enabled) {
      t_add_us = micros_between(add_begin, Clock::now());
    }

    const auto truncate_begin =
        profile_enabled ? Clock::now() : Clock::time_point{};
    ciphertext.truncate_to_size(2);
    if (profile_enabled) {
      t_truncate_us = micros_between(truncate_begin, Clock::now());
      const auto total_us = micros_between(total_begin, Clock::now());
      std::cerr << "[HEU_RELIN_PROFILE] key_switch_us=" << t_key_switch_us
                << " modswitch_us=" << t_modswitch_us
                << " repr_us=" << t_repr_us << " add_us=" << t_add_us
                << " truncate_us=" << t_truncate_us << " total_us=" << total_us
                << '\n';
    }

  } catch (const std::exception &e) {
    throw MathException("Failed to relinearize: " + std::string(e.what()));
  }
}

// Relinearization method (returns new ciphertext)
Ciphertext RelinearizationKey::relinearize_new(
    const Ciphertext &ciphertext) const {
  if (!impl_) {
    throw ParameterException("Relinearization key is not initialized");
  }

  const auto &ct_polys = ciphertext.polynomials();
  if (ct_polys.size() != 3) {
    throw ParameterException(
        "Only supports relinearization of ciphertext with 3 parts");
  }

  if (ciphertext.level() != impl_->switching_key.ciphertext_level()) {
    throw ParameterException("Ciphertext has incorrect level");
  }

  try {
    const ::bfv::math::rq::Poly *c2_ptr = &ct_polys[2];
    ::bfv::math::rq::Poly c2_owned;
    const auto target_repr = ct_polys[0].representation();
    if (c2_ptr->representation() !=
        ::bfv::math::rq::Representation::PowerBasis) {
      c2_owned = *c2_ptr;
      c2_owned.change_representation(
          ::bfv::math::rq::Representation::PowerBasis);
      c2_ptr = &c2_owned;
    }

    const bool can_fuse_power_output =
        target_repr == ::bfv::math::rq::Representation::PowerBasis &&
        impl_->switching_key.ciphertext_level() ==
            impl_->switching_key.ksk_level();
    const auto key_switch_output_representation =
        can_fuse_power_output ? ::bfv::math::rq::Representation::Ntt
                              : ::bfv::math::rq::Representation::PowerBasis;

    thread_local ::bfv::math::rq::Poly tl_c0_delta;
    thread_local ::bfv::math::rq::Poly tl_c1_delta;
    impl_->switching_key.apply_key_switch_into(
        *c2_ptr, tl_c0_delta, tl_c1_delta, key_switch_output_representation);
    auto &c0_delta = tl_c0_delta;
    auto &c1_delta = tl_c1_delta;

    if (!can_fuse_power_output &&
        (c0_delta.representation() !=
             ::bfv::math::rq::Representation::PowerBasis ||
         c1_delta.representation() !=
             ::bfv::math::rq::Representation::PowerBasis)) {
      c0_delta.change_representation(
          ::bfv::math::rq::Representation::PowerBasis);
      c1_delta.change_representation(
          ::bfv::math::rq::Representation::PowerBasis);
    }

    if (!can_fuse_power_output && c0_delta.ctx() != ct_polys[0].ctx()) {
      c0_delta.drop_to_context(ct_polys[0].ctx());
      c1_delta.drop_to_context(ct_polys[1].ctx());
    }
    if (!can_fuse_power_output &&
        target_repr != ::bfv::math::rq::Representation::PowerBasis) {
      c0_delta.change_representation(target_repr);
      c1_delta.change_representation(target_repr);
    }

    auto out0 = ct_polys[0];
    auto out1 = ct_polys[1];
    if (can_fuse_power_output) {
      FusedInverseLazyAddPair(c0_delta, c1_delta, out0, out1);
    } else {
      out0 += c0_delta;
      out1 += c1_delta;
    }

    std::vector<::bfv::math::rq::Poly> result_polys;
    result_polys.reserve(2);
    result_polys.emplace_back(std::move(out0));
    result_polys.emplace_back(std::move(out1));
    return Ciphertext::from_polynomials_with_level(
        std::move(result_polys), ciphertext.parameters(), ciphertext.level());
  } catch (const std::exception &e) {
    throw MathException("Failed to relinearize: " + std::string(e.what()));
  }
}

std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly>
RelinearizationKey::relinearize_poly(const ::bfv::math::rq::Poly &c2) const {
  return relinearize_poly(c2, ::bfv::math::rq::Representation::Ntt);
}

std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly>
RelinearizationKey::relinearize_poly(
    const ::bfv::math::rq::Poly &c2,
    ::bfv::math::rq::Representation output_representation) const {
  ::bfv::math::rq::Poly c0_delta;
  ::bfv::math::rq::Poly c1_delta;
  relinearize_poly(c2, c0_delta, c1_delta, output_representation);
  return std::make_pair(std::move(c0_delta), std::move(c1_delta));
}

void RelinearizationKey::relinearize_poly(
    const ::bfv::math::rq::Poly &c2, ::bfv::math::rq::Poly &c0_delta,
    ::bfv::math::rq::Poly &c1_delta,
    ::bfv::math::rq::Representation output_representation) const {
  if (!impl_) {
    throw ParameterException("Relinearization key is not initialized");
  }

  impl_->switching_key.apply_key_switch_into(c2, c0_delta, c1_delta,
                                             output_representation);
}

// Accessors
std::shared_ptr<BfvParameters> RelinearizationKey::parameters() const {
  return impl_ ? impl_->switching_key.parameters() : nullptr;
}

bool RelinearizationKey::empty() const {
  return !impl_ || impl_->switching_key.empty();
}

size_t RelinearizationKey::ciphertext_level() const {
  return impl_ ? impl_->switching_key.ciphertext_level() : 0;
}

size_t RelinearizationKey::key_level() const {
  return impl_ ? impl_->switching_key.ksk_level() : 0;
}

const KeySwitchingKey &RelinearizationKey::key_switching_key() const {
  if (!impl_) {
    throw ParameterException("Relinearization key is not initialized");
  }
  return impl_->switching_key;
}

// Equality operators
bool RelinearizationKey::operator==(const RelinearizationKey &other) const {
  if (!impl_ && !other.impl_) return true;
  if (!impl_ || !other.impl_) return false;

  return impl_->switching_key == other.impl_->switching_key;
}

bool RelinearizationKey::operator!=(const RelinearizationKey &other) const {
  return !(*this == other);
}

// Serialization implementation
yacl::Buffer RelinearizationKey::Serialize() const {
  if (!impl_ || impl_->switching_key.empty()) {
    throw SerializationException("RelinearizationKey is not initialized");
  }

  auto serialized_ksk = impl_->switching_key.Serialize();
  RelinearizationKeyData data;
  data.key_switching_key.assign(
      serialized_ksk.data<uint8_t>(),
      serialized_ksk.data<uint8_t>() + serialized_ksk.size());
  return MsgpackSerializer::Serialize(data);
}

void RelinearizationKey::Deserialize(yacl::ByteContainerView in,
                                     std::shared_ptr<BfvParameters> params) {
  *this = from_bytes(in, std::move(params));
}

RelinearizationKey RelinearizationKey::from_bytes(
    yacl::ByteContainerView bytes, std::shared_ptr<BfvParameters> params) {
  if (!params) {
    throw SerializationException(
        "Parameters are required for RelinearizationKey");
  }

  try {
    auto data = MsgpackSerializer::Deserialize<RelinearizationKeyData>(bytes);
    auto switching_key = KeySwitchingKey::from_bytes(
        yacl::ByteContainerView(data.key_switching_key.data(),
                                data.key_switching_key.size()),
        params);
    return from_key_switching_key(std::move(switching_key), std::move(params));
  } catch (const SerializationException &) {
    throw;
  } catch (const std::exception &e) {
    throw SerializationException("Failed to deserialize RelinearizationKey: " +
                                 std::string(e.what()));
  }
}

RelinearizationKey RelinearizationKey::from_key_switching_key(
    KeySwitchingKey switching_key, std::shared_ptr<BfvParameters> params) {
  // Create RelinearizationKey from the key switching key
  (void)params;  // params not needed for this constructor
  auto impl = std::make_unique<Impl>(std::move(switching_key));
  return RelinearizationKey(std::move(impl));
}

}  // namespace bfv
}  // namespace crypto
