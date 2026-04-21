#include "crypto/evaluation_key.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "math/context.h"
#include "math/modulus.h"
#include "math/poly.h"
#include "math/representation.h"
#include "math/substitution_exponent.h"

// Serialization includes
#include "crypto/exceptions.h"
#include "crypto/galois_key.h"
#include "crypto/operators.h"
#include "crypto/secret_key.h"
#include "crypto/serialization/msgpack_adaptors.h"

namespace crypto {
namespace bfv {

// EvaluationKey::Impl - PIMPL implementation
class EvaluationKey::Impl {
 public:
  std::shared_ptr<BfvParameters> bfv_params;
  size_t ct_level;
  size_t ek_level;
  std::unordered_map<size_t, GaloisKey> galois_keys_map;
  std::vector<::bfv::math::rq::Poly> expansion_monomials;
  std::shared_ptr<const std::unordered_map<size_t, size_t>>
      rotation_to_gk_exponent_map;

  Impl() = default;
  ~Impl() = default;

  // Copy constructor
  Impl(const Impl &other)
      : bfv_params(other.bfv_params),
        ct_level(other.ct_level),
        ek_level(other.ek_level),
        galois_keys_map(other.galois_keys_map),
        expansion_monomials(other.expansion_monomials),
        rotation_to_gk_exponent_map(other.rotation_to_gk_exponent_map) {}

  // Move constructor
  Impl(Impl &&other) noexcept
      : bfv_params(std::move(other.bfv_params)),
        ct_level(other.ct_level),
        ek_level(other.ek_level),
        galois_keys_map(std::move(other.galois_keys_map)),
        expansion_monomials(std::move(other.expansion_monomials)),
        rotation_to_gk_exponent_map(
            std::move(other.rotation_to_gk_exponent_map)) {}

  // Assignment operators
  Impl &operator=(const Impl &other) {
    if (this != &other) {
      bfv_params = other.bfv_params;
      ct_level = other.ct_level;
      ek_level = other.ek_level;
      galois_keys_map = other.galois_keys_map;
      expansion_monomials = other.expansion_monomials;
      rotation_to_gk_exponent_map = other.rotation_to_gk_exponent_map;
    }
    return *this;
  }

  Impl &operator=(Impl &&other) noexcept {
    if (this != &other) {
      bfv_params = std::move(other.bfv_params);
      ct_level = other.ct_level;
      ek_level = other.ek_level;
      galois_keys_map = std::move(other.galois_keys_map);
      expansion_monomials = std::move(other.expansion_monomials);
      rotation_to_gk_exponent_map =
          std::move(other.rotation_to_gk_exponent_map);
    }
    return *this;
  }
};

// EvaluationKey implementation
EvaluationKey::EvaluationKey(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

EvaluationKey::~EvaluationKey() = default;

EvaluationKey::EvaluationKey(const EvaluationKey &other)
    : impl_(std::make_unique<Impl>(*other.impl_)) {}

EvaluationKey &EvaluationKey::operator=(const EvaluationKey &other) {
  if (this != &other) {
    *impl_ = *other.impl_;
  }
  return *this;
}

EvaluationKey::EvaluationKey(EvaluationKey &&other) noexcept = default;
EvaluationKey &EvaluationKey::operator=(EvaluationKey &&other) noexcept =
    default;

std::shared_ptr<BfvParameters> EvaluationKey::parameters() const {
  return impl_->bfv_params;
}

size_t EvaluationKey::ciphertext_level() const { return impl_->ct_level; }

size_t EvaluationKey::evaluation_key_level() const { return impl_->ek_level; }

bool EvaluationKey::empty() const {
  return !impl_ || impl_->galois_keys_map.empty();
}

bool EvaluationKey::operator==(const EvaluationKey &other) const {
  if (!impl_ && !other.impl_) {
    return true;
  }
  if (!impl_ || !other.impl_) {
    return false;
  }
  return impl_->bfv_params == other.impl_->bfv_params &&
         impl_->ct_level == other.impl_->ct_level &&
         impl_->galois_keys_map == other.impl_->galois_keys_map &&
         ((!impl_->rotation_to_gk_exponent_map &&
           !other.impl_->rotation_to_gk_exponent_map) ||
          (impl_->rotation_to_gk_exponent_map &&
           other.impl_->rotation_to_gk_exponent_map &&
           *impl_->rotation_to_gk_exponent_map ==
               *other.impl_->rotation_to_gk_exponent_map));
}

bool EvaluationKey::operator!=(const EvaluationKey &other) const {
  return !(*this == other);
}

bool EvaluationKey::supports_inner_sum() const {
  size_t degree = impl_->bfv_params->degree();
  bool ret = impl_->galois_keys_map.find(degree * 2 - 1) !=
             impl_->galois_keys_map.end();

  size_t i = 1;
  while (i < degree / 2) {
    auto it = impl_->rotation_to_gk_exponent_map->find(i);
    if (it == impl_->rotation_to_gk_exponent_map->end()) {
      ret = false;
      break;
    }
    ret = ret && (impl_->galois_keys_map.find(it->second) !=
                  impl_->galois_keys_map.end());
    i *= 2;
  }

  return ret;
}

bool EvaluationKey::supports_row_rotation() const {
  // Check if we have the required Galois key for row rotation
  size_t degree = impl_->bfv_params->degree();
  size_t required_index = degree * 2 - 1;
  return impl_->galois_keys_map.find(required_index) !=
         impl_->galois_keys_map.end();
}

bool EvaluationKey::supports_column_rotation_by(size_t steps) const {
  // Check if we have the required Galois key for column rotation
  auto it = impl_->rotation_to_gk_exponent_map->find(steps);
  if (it == impl_->rotation_to_gk_exponent_map->end()) {
    return false;
  }
  return impl_->galois_keys_map.find(it->second) !=
         impl_->galois_keys_map.end();
}

bool EvaluationKey::supports_expansion(size_t level) const {
  if (level == 0) {
    return true;
  }

  if (impl_->ek_level == impl_->bfv_params->moduli().size()) {
    return false;
  }

  size_t degree = impl_->bfv_params->degree();
  [[maybe_unused]] size_t leading_zeros = 0;
  if (degree > 0) {
    // Calculate leading zeros for size_t
    if (sizeof(size_t) == 8) {
      leading_zeros = __builtin_clzll(degree);
    } else {
      leading_zeros = __builtin_clz(degree);
    }
  }
  bool ret = level < leading_zeros;

  for (size_t l = 0; l < level; l++) {
    size_t gk_index = (degree >> l) + 1;
    bool has_key =
        (impl_->galois_keys_map.find(gk_index) != impl_->galois_keys_map.end());
    ret = ret && has_key;
  }

  return ret;
}

Ciphertext EvaluationKey::computes_inner_sum(
    const Ciphertext &ciphertext) const {
  if (!supports_inner_sum()) {
    throw ParameterException("EvaluationKey does not support inner sum");
  }

  auto out = ciphertext;

  // Apply column rotations for powers of 2
  size_t i = 1;
  while (i < ciphertext.parameters()->degree() / 2) {
    auto gk_exp_it = impl_->rotation_to_gk_exponent_map->find(i);
    if (gk_exp_it == impl_->rotation_to_gk_exponent_map->end()) {
      throw MathException("Missing Galois key for inner sum");
    }
    auto gk_it = impl_->galois_keys_map.find(gk_exp_it->second);
    if (gk_it == impl_->galois_keys_map.end()) {
      throw MathException("Missing Galois key for inner sum");
    }
    auto rotated = gk_it->second.apply(out);
    out = out + rotated;
    i *= 2;
  }

  // Apply row rotation
  auto row_gk_it =
      impl_->galois_keys_map.find(ciphertext.parameters()->degree() * 2 - 1);
  if (row_gk_it == impl_->galois_keys_map.end()) {
    throw MathException("Missing Galois key for row rotation in inner sum");
  }
  auto row_rotated = row_gk_it->second.apply(out);
  out = out + row_rotated;

  return out;
}

Ciphertext EvaluationKey::rotates_rows(const Ciphertext &ciphertext) const {
  if (!supports_row_rotation()) {
    throw ParameterException("EvaluationKey does not support row rotation");
  }

  auto gk_it =
      impl_->galois_keys_map.find(ciphertext.parameters()->degree() * 2 - 1);
  if (gk_it == impl_->galois_keys_map.end()) {
    throw MathException("Missing Galois key for row rotation");
  }

  return gk_it->second.apply(ciphertext);
}

Ciphertext EvaluationKey::rotates_columns_by(const Ciphertext &ciphertext,
                                             size_t steps) const {
  if (!supports_column_rotation_by(steps)) {
    throw ParameterException(
        "EvaluationKey does not support column rotation by " +
        std::to_string(steps));
  }

  auto gk_exp_it = impl_->rotation_to_gk_exponent_map->find(steps);
  if (gk_exp_it == impl_->rotation_to_gk_exponent_map->end()) {
    throw MathException("Missing rotation index mapping");
  }

  auto gk_it = impl_->galois_keys_map.find(gk_exp_it->second);
  if (gk_it == impl_->galois_keys_map.end()) {
    throw MathException("Missing Galois key for column rotation");
  }

  return gk_it->second.apply(ciphertext);
}

std::vector<Ciphertext> EvaluationKey::expands(const Ciphertext &ciphertext,
                                               size_t size) const {
  size_t next_power_of_two = 1;
  while (next_power_of_two < size) {
    next_power_of_two <<= 1;
  }
  size_t level = 0;
  if (next_power_of_two > 1) {
    size_t temp = next_power_of_two;
    while (temp > 1) {
      temp >>= 1;
      level++;
    }
  }

  if (level == 0) {
    return {ciphertext};
  }

  if (!supports_expansion(level)) {
    throw ParameterException(
        "EvaluationKey does not support expansion at level " +
        std::to_string(level));
  }

  // Initialize output with zero ciphertexts.
  std::vector<Ciphertext> out;
  out.reserve(1ULL << level);
  for (size_t i = 0; i < (1ULL << level); i++) {
    // Create zero ciphertext at the same level as input ciphertext
    auto ctx = impl_->bfv_params->ctx_at_level(ciphertext.level());
    auto c0 =
        ::bfv::math::rq::Poly::zero(ctx, ::bfv::math::rq::Representation::Ntt);
    auto c1 =
        ::bfv::math::rq::Poly::zero(ctx, ::bfv::math::rq::Representation::Ntt);
    std::vector<::bfv::math::rq::Poly> zero_polys = {std::move(c0),
                                                     std::move(c1)};
    out.push_back(Ciphertext::from_polynomials_with_level(
        std::move(zero_polys), impl_->bfv_params, ciphertext.level()));
  }

  out[0] = ciphertext;

  for (size_t l = 0; l < level; l++) {
    // Precomputed monomial for this expansion stage.
    const auto &monomial = impl_->expansion_monomials[l];

    size_t gk_index = (impl_->bfv_params->degree() >> l) + 1;
    auto gk_it = impl_->galois_keys_map.find(gk_index);
    if (gk_it == impl_->galois_keys_map.end()) {
      throw MathException("Missing Galois key for expansion at level " +
                          std::to_string(l));
    }
    const auto &galois_key = gk_it->second;

    // Process current frontier.
    for (size_t i = 0; i < (1ULL << l); i++) {
      auto sub = galois_key.apply(out[i]);

      size_t expanded_index = (1ULL << l) | i;
      if (expanded_index < size) {
        out[expanded_index] = out[i] - sub;

        // Apply monomial multiplication to each polynomial component.
        auto &ct_ref = out[expanded_index];
        auto modified_polys = ct_ref.polynomials();
        for (size_t j = 0; j < modified_polys.size(); j++) {
          auto original_rep = modified_polys[j].representation();
          if (original_rep != ::bfv::math::rq::Representation::Ntt) {
            modified_polys[j].change_representation(
                ::bfv::math::rq::Representation::Ntt);
          }
          modified_polys[j] = modified_polys[j] * monomial;
          if (original_rep != ::bfv::math::rq::Representation::Ntt) {
            modified_polys[j].change_representation(original_rep);
          }
        }

        // Rebuild ciphertext with transformed polynomials.
        out[expanded_index] = Ciphertext::from_polynomials_with_level(
            std::move(modified_polys), impl_->bfv_params, ct_ref.level());
      }

      out[i] = out[i] + sub;
    }
  }

  // Trim to requested size.
  if (out.size() > size) {
    out.resize(size);
  }

  return out;
}

std::shared_ptr<const std::unordered_map<size_t, size_t>>
EvaluationKey::build_rotation_exponent_map(
    std::shared_ptr<BfvParameters> params) {
  static std::unordered_map<
      size_t, std::shared_ptr<const std::unordered_map<size_t, size_t>>>
      cache;

  const size_t degree = params->degree();
  auto cached = cache.find(degree);
  if (cached != cache.end()) {
    return cached->second;
  }

  auto map = std::make_shared<std::unordered_map<size_t, size_t>>();
  map->reserve(degree / 2);

  uint64_t q_val = 2 * degree;
  auto q_opt = ::bfv::math::zq::Modulus::New(q_val);
  if (!q_opt) {
    throw ParameterException("Failed to create modulus");
  }
  auto q = *q_opt;

  for (size_t i = 1; i < degree / 2; i++) {
    (*map)[i] = static_cast<size_t>(q.Pow(3, i));
  }

  auto inserted = cache.emplace(degree, map);
  return inserted.first->second;
}

const std::unordered_map<size_t, GaloisKey> &EvaluationKey::galois_keys()
    const {
  if (!impl_) {
    throw ParameterException("EvaluationKey is not initialized");
  }
  return impl_->galois_keys_map;
}

// Serialization implementation
yacl::Buffer EvaluationKey::Serialize() const {
  if (!impl_ || !impl_->bfv_params) {
    throw SerializationException("EvaluationKey is not initialized");
  }

  EvaluationKeyData data;
  data.ciphertext_level = impl_->ct_level;
  data.evaluation_key_level = impl_->ek_level;
  data.galois_keys.reserve(impl_->galois_keys_map.size());
  for (const auto &[index, galois_key] : impl_->galois_keys_map) {
    auto serialized = galois_key.Serialize();
    std::vector<uint8_t> payload(
        serialized.data<uint8_t>(),
        serialized.data<uint8_t>() + serialized.size());
    data.galois_keys.emplace_back(index, std::move(payload));
  }
  return MsgpackSerializer::Serialize(data);
}

void EvaluationKey::Deserialize(yacl::ByteContainerView in,
                                std::shared_ptr<BfvParameters> params) {
  *this = from_bytes(in, std::move(params));
}

EvaluationKey EvaluationKey::from_bytes(yacl::ByteContainerView bytes,
                                        std::shared_ptr<BfvParameters> params) {
  if (!params) {
    throw SerializationException("Parameters are required for EvaluationKey");
  }

  try {
    auto data = MsgpackSerializer::Deserialize<EvaluationKeyData>(bytes);
    std::unordered_map<size_t, GaloisKey> galois_keys;
    galois_keys.reserve(data.galois_keys.size());
    for (const auto &[index, payload] : data.galois_keys) {
      galois_keys.emplace(
          index,
          GaloisKey::from_bytes(
              yacl::ByteContainerView(payload.data(), payload.size()), params));
    }
    return from_components(std::move(params), data.ciphertext_level,
                           data.evaluation_key_level, std::move(galois_keys));
  } catch (const SerializationException &) {
    throw;
  } catch (const std::exception &e) {
    throw SerializationException("Failed to deserialize EvaluationKey: " +
                                 std::string(e.what()));
  }
}

EvaluationKey EvaluationKey::from_components(
    std::shared_ptr<BfvParameters> params, size_t ciphertext_level,
    size_t evaluation_key_level,
    std::unordered_map<size_t, GaloisKey> galois_keys) {
  // Create EvaluationKey::Impl with the components
  auto impl = std::make_unique<Impl>();
  impl->bfv_params = params;
  impl->ct_level = ciphertext_level;
  impl->ek_level = evaluation_key_level;
  impl->galois_keys_map = std::move(galois_keys);
  impl->rotation_to_gk_exponent_map = build_rotation_exponent_map(params);
  auto ciphertext_ctx = params->ctx_at_level(ciphertext_level);
  size_t degree = params->degree();
  size_t expansion_levels = 0;
  while ((1ULL << expansion_levels) < degree) {
    size_t gk_index = (degree >> expansion_levels) + 1;
    if (impl->galois_keys_map.find(gk_index) == impl->galois_keys_map.end()) {
      break;
    }
    ++expansion_levels;
  }

  impl->expansion_monomials.reserve(expansion_levels);
  for (size_t i = 0; i < expansion_levels; ++i) {
    std::vector<int64_t> coeffs(degree, 0);
    coeffs[degree - (1ULL << i)] = -1;
    auto poly = ::bfv::math::rq::Poly::from_i64_vector(
        coeffs, ciphertext_ctx, true,
        ::bfv::math::rq::Representation::PowerBasis);
    poly.change_representation(::bfv::math::rq::Representation::Ntt);
    impl->expansion_monomials.push_back(std::move(poly));
  }

  return EvaluationKey(std::move(impl));
}

// EvaluationKeyBuilder::Impl - PIMPL implementation
class EvaluationKeyBuilder::Impl {
 public:
  const SecretKey *source_secret_key_;
  size_t build_ct_level;
  size_t build_ek_level;
  std::unordered_map<size_t, size_t> enabled_column_rotations;
  bool inner_sum_enabled;
  bool row_rotation_enabled;
  size_t requested_expansion_level;
  std::shared_ptr<const std::unordered_map<size_t, size_t>>
      rotation_to_gk_exponent_map;

  Impl(const SecretKey &secret_key, size_t ciphertext_level,
       size_t evaluation_key_level)
      : source_secret_key_(&secret_key),
        build_ct_level(ciphertext_level),
        build_ek_level(evaluation_key_level),
        inner_sum_enabled(false),
        row_rotation_enabled(false),
        requested_expansion_level(0) {
    rotation_to_gk_exponent_map = EvaluationKey::build_rotation_exponent_map(
        source_secret_key_->parameters());
  }
};

// EvaluationKeyBuilder implementation
EvaluationKeyBuilder::EvaluationKeyBuilder(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

EvaluationKeyBuilder::~EvaluationKeyBuilder() = default;

EvaluationKeyBuilder::EvaluationKeyBuilder(const EvaluationKeyBuilder &other)
    : impl_(std::make_unique<Impl>(*other.impl_)) {}

EvaluationKeyBuilder &EvaluationKeyBuilder::operator=(
    const EvaluationKeyBuilder &other) {
  if (this != &other) {
    *impl_ = *other.impl_;
  }
  return *this;
}

EvaluationKeyBuilder::EvaluationKeyBuilder(
    EvaluationKeyBuilder &&other) noexcept = default;
EvaluationKeyBuilder &EvaluationKeyBuilder::operator=(
    EvaluationKeyBuilder &&other) noexcept = default;

EvaluationKeyBuilder EvaluationKeyBuilder::create(const SecretKey &sk) {
  auto impl = std::make_unique<Impl>(sk, 0, 0);
  return EvaluationKeyBuilder(std::move(impl));
}

EvaluationKeyBuilder EvaluationKeyBuilder::create_leveled(
    const SecretKey &sk, size_t ciphertext_level, size_t evaluation_key_level) {
  // Validate level parameters
  if (evaluation_key_level > ciphertext_level) {
    throw ParameterException(
        "Evaluation key level cannot be greater than ciphertext level");
  }

  auto impl =
      std::make_unique<Impl>(sk, ciphertext_level, evaluation_key_level);
  return EvaluationKeyBuilder(std::move(impl));
}

EvaluationKeyBuilder &EvaluationKeyBuilder::enable_inner_sum() {
  impl_->inner_sum_enabled = true;
  return *this;
}

EvaluationKeyBuilder &EvaluationKeyBuilder::enable_row_rotation() {
  impl_->row_rotation_enabled = true;
  return *this;
}

EvaluationKeyBuilder &EvaluationKeyBuilder::enable_column_rotation(
    size_t steps) {
  // Validate that steps is not 0 (no-op rotation)
  if (steps == 0) {
    throw ParameterException("Column rotation steps cannot be 0");
  }

  // Validate that steps is within valid range
  size_t max_steps = impl_->source_secret_key_->parameters()->degree() / 2;
  if (steps >= max_steps) {
    throw ParameterException("Column rotation steps must be less than " +
                             std::to_string(max_steps));
  }

  impl_->enabled_column_rotations[steps] = steps;
  return *this;
}

EvaluationKeyBuilder &EvaluationKeyBuilder::enable_expansion(size_t level) {
  // Calculate maximum valid expansion level
  size_t degree = impl_->source_secret_key_->parameters()->degree();
  size_t max_expansion = 64 - __builtin_clzll(degree);

  // Validate that level is within valid range
  if (level >= max_expansion) {
    throw ParameterException("Expansion level " + std::to_string(level) +
                             " must be less than " +
                             std::to_string(max_expansion));
  }

  // Store the maximum expansion level we want to support
  // The build() method will generate keys for levels 0 to level-1
  impl_->requested_expansion_level = level;
  return *this;
}

EvaluationKey EvaluationKeyBuilder::build(std::mt19937_64 &rng) {
  auto ek_impl = std::make_unique<EvaluationKey::Impl>();
  ek_impl->bfv_params = impl_->source_secret_key_->parameters();
  ek_impl->ct_level = impl_->build_ct_level;
  ek_impl->ek_level = impl_->build_ek_level;
  ek_impl->rotation_to_gk_exponent_map = impl_->rotation_to_gk_exponent_map;

  // Collect all required Galois key indices
  std::unordered_set<size_t> indices;

  // Add column rotation indices
  for (const auto &[steps, _] : impl_->enabled_column_rotations) {
    auto it = impl_->rotation_to_gk_exponent_map->find(steps);
    if (it != impl_->rotation_to_gk_exponent_map->end()) {
      indices.insert(it->second);
    }
  }

  if (impl_->row_rotation_enabled) {
    indices.insert(impl_->source_secret_key_->parameters()->degree() * 2 - 1);
  }

  if (impl_->inner_sum_enabled) {
    // Include all indices needed for inner-sum rotations.
    indices.insert(impl_->source_secret_key_->parameters()->degree() * 2 - 1);
    size_t i = 1;
    while (i < impl_->source_secret_key_->parameters()->degree() / 2) {
      auto it = ek_impl->rotation_to_gk_exponent_map->find(i);
      if (it != ek_impl->rotation_to_gk_exponent_map->end()) {
        indices.insert(it->second);
      }
      i <<= 1;
    }
  }

  // Add expansion indices - generate keys for levels 0 to
  // requested_expansion_level-1 This allows
  // supports_expansion(requested_expansion_level) to return true, but
  // supports_expansion(requested_expansion_level+1) to return false
  for (size_t l = 0; l < impl_->requested_expansion_level; l++) {
    size_t gk_index =
        (impl_->source_secret_key_->parameters()->degree() >> l) + 1;
    indices.insert(gk_index);
  }

  // Create monomials for expansion
  auto ciphertext_ctx = impl_->source_secret_key_->parameters()->ctx_at_level(
      impl_->build_ct_level);
  size_t param_degree = impl_->source_secret_key_->parameters()->degree();

  // Calculate ilog2 of degree (max possible expansion level)
  size_t ilog2_degree = 0;
  size_t temp = param_degree;
  while (temp > 1) {
    temp >>= 1;
    ilog2_degree++;
  }

  // Only generate monomials required for the requested expansion level
  size_t required_monomials =
      std::min(ilog2_degree, impl_->requested_expansion_level);

  ek_impl->expansion_monomials.reserve(required_monomials);
  for (size_t i = 0; i < required_monomials; i++) {
    // monomial[par.degree() - (1 << l)] = -1;
    std::vector<int64_t> coeffs(param_degree, 0);
    size_t pos = param_degree - (1ULL << i);
    if (pos < param_degree) {
      coeffs[pos] = -1;
    }

    // Convert to polynomial in PowerBasis first, then convert to NTT
    auto poly = ::bfv::math::rq::Poly::from_i64_vector(
        coeffs, ciphertext_ctx, true,
        ::bfv::math::rq::Representation::PowerBasis);
    // Convert to NTT representation to match ciphertext polynomials
    poly.change_representation(::bfv::math::rq::Representation::Ntt);
    ek_impl->expansion_monomials.push_back(std::move(poly));
  }

  // Generate Galois keys for all required indices
  for (size_t index : indices) {
    try {
      auto galois_key =
          GaloisKey::create(*impl_->source_secret_key_, index,
                            impl_->build_ct_level, impl_->build_ek_level, rng);
      ek_impl->galois_keys_map.emplace(index, std::move(galois_key));
    } catch (const std::exception &e) {
      throw;
    }
  }

  return EvaluationKey(std::move(ek_impl));
}

}  // namespace bfv
}  // namespace crypto
