#include "crypto/ciphertext.h"

#include <algorithm>
#include <stdexcept>

#include "crypto/bfv_parameters.h"
#include "crypto/plaintext.h"
#include "crypto/serialization/msgpack_adaptors.h"
#include "crypto/serialization/serialization_exceptions.h"
#include "math/context.h"
#include "math/poly.h"
#include "math/representation.h"

namespace crypto {
namespace bfv {

// Alias to avoid conflict with crypto::bfv::SerializationException
// Use fully qualified namespace to avoid conflicts with
// crypto::bfv::SerializationException
namespace ser = serialization;

namespace {

void ValidateCiphertextPolynomials(
    const std::vector<::bfv::math::rq::Poly> &polynomials) {
  if (polynomials.size() < 2) {
    throw ParameterException(
        "Ciphertext must contain at least 2 polynomials, got " +
        std::to_string(polynomials.size()));
  }

  auto expected_ctx = polynomials[0].ctx();
  auto expected_repr = polynomials[0].representation();

  for (const auto &poly : polynomials) {
    if (poly.representation() != expected_repr) {
      throw ParameterException(
          "All polynomials must have the same representation");
    }
    if (poly.ctx() != expected_ctx) {
      throw ParameterException("All polynomials must have the same context");
    }
  }
}

}  // namespace

// Ciphertext::Impl - PIMPL implementation
class Ciphertext::Impl {
 public:
  std::shared_ptr<BfvParameters> par;
  std::optional<std::array<uint8_t, 32>> seed;
  std::vector<::bfv::math::rq::Poly> c;
  size_t level;

  Impl() : level(0) {}

  // Validate that all polynomials have the same context and representation.
  bool validate_polynomials() const {
    if (c.size() < 2) {
      return false;
    }

    auto expected_ctx = c[0].ctx();
    auto expected_repr = c[0].representation();

    for (const auto &poly : c) {
      if (poly.ctx() != expected_ctx ||
          poly.representation() != expected_repr) {
        return false;
      }
    }

    return true;
  }
};

// Ciphertext implementation
Ciphertext::Ciphertext() : pImpl(std::make_unique<Impl>()) {}

Ciphertext::~Ciphertext() = default;

Ciphertext::Ciphertext(const Ciphertext &other)
    : pImpl(std::make_unique<Impl>(*other.pImpl)) {}

Ciphertext &Ciphertext::operator=(const Ciphertext &other) {
  if (this != &other) {
    pImpl = std::make_unique<Impl>(*other.pImpl);
  }
  return *this;
}

Ciphertext::Ciphertext(Ciphertext &&other) noexcept = default;
Ciphertext &Ciphertext::operator=(Ciphertext &&other) noexcept = default;

Ciphertext::Ciphertext(std::unique_ptr<Impl> impl) : pImpl(std::move(impl)) {}

bool Ciphertext::operator==(const Ciphertext &other) const {
  if (!pImpl->par || !other.pImpl->par) {
    return false;
  }

  bool eq = (*pImpl->par == *other.pImpl->par);
  eq &= (pImpl->level == other.pImpl->level);
  eq &= (pImpl->seed == other.pImpl->seed);
  eq &= (pImpl->c.size() == other.pImpl->c.size());

  if (eq) {
    for (size_t i = 0; i < pImpl->c.size(); ++i) {
      // Note: This is a simplified comparison - in a full implementation
      // we would need proper polynomial equality comparison
      if (pImpl->c[i].ctx() != other.pImpl->c[i].ctx()) {
        eq = false;
        break;
      }
    }
  }

  return eq;
}

bool Ciphertext::operator!=(const Ciphertext &other) const {
  return !(*this == other);
}

// Static factory methods
Ciphertext Ciphertext::from_polynomials(
    const std::vector<::bfv::math::rq::Poly> &polynomials,
    std::shared_ptr<BfvParameters> params, ::bfv::util::ArenaHandle pool) {
  return from_polynomials(std::vector<::bfv::math::rq::Poly>(polynomials),
                          std::move(params), pool);
}

Ciphertext Ciphertext::from_polynomials(
    std::vector<::bfv::math::rq::Poly> &&polynomials,
    std::shared_ptr<BfvParameters> params, ::bfv::util::ArenaHandle pool) {
  if (!params) {
    throw ParameterException("Parameters cannot be null");
  }

  ValidateCiphertextPolynomials(polynomials);

  // Determine the level from the context
  size_t level;
  try {
    auto expected_ctx = polynomials[0].ctx();
    // Cast away const for level_of_ctx call
    auto non_const_ctx =
        std::const_pointer_cast<::bfv::math::rq::Context>(expected_ctx);
    level = params->level_of_ctx(non_const_ctx);
  } catch (const BfvException &e) {
    throw ParameterException("Invalid context for parameters: " +
                             std::string(e.what()));
  }

  // Create implementation
  auto impl = std::make_unique<Impl>();
  impl->par = params;
  impl->c = std::move(polynomials);
  impl->level = level;
  impl->seed = std::nullopt;

  return Ciphertext(std::move(impl));
}

Ciphertext Ciphertext::from_polynomials_with_level(
    const std::vector<::bfv::math::rq::Poly> &polynomials,
    std::shared_ptr<BfvParameters> params, size_t level,
    ::bfv::util::ArenaHandle pool) {
  return from_polynomials_with_level(
      std::vector<::bfv::math::rq::Poly>(polynomials), std::move(params), level,
      pool);
}

Ciphertext Ciphertext::from_polynomials_with_level(
    std::vector<::bfv::math::rq::Poly> &&polynomials,
    std::shared_ptr<BfvParameters> params, size_t level,
    ::bfv::util::ArenaHandle pool) {
  if (!params) {
    throw ParameterException("Parameters cannot be null");
  }

  ValidateCiphertextPolynomials(polynomials);

  // Create implementation with explicit level
  auto impl = std::make_unique<Impl>();
  impl->par = params;
  impl->c = std::move(polynomials);
  impl->level = level;  // Use the explicitly provided level
  impl->seed = std::nullopt;

  return Ciphertext(std::move(impl));
}

Ciphertext Ciphertext::zero(std::shared_ptr<BfvParameters> params,
                            ::bfv::util::ArenaHandle pool) {
  if (!params) {
    throw ParameterException("Parameters cannot be null");
  }

  auto impl = std::make_unique<Impl>();
  impl->par = params;
  impl->level = 0;
  impl->seed = std::nullopt;
  // Note: c vector is left empty for zero ciphertext

  return Ciphertext(std::move(impl));
}

// Level management
void Ciphertext::mod_switch_to_last_level() {
  if (!pImpl->par) {
    throw MathException("Ciphertext has no parameters");
  }

  try {
    pImpl->level = pImpl->par->max_level();
    auto last_ctx = pImpl->par->ctx_at_level(pImpl->level);
    pImpl->seed = std::nullopt;  // Clear seed when modifying

    for (auto &ci : pImpl->c) {
      if (ci.ctx() != last_ctx) {
        auto original_repr = ci.representation();
        ci.change_representation(::bfv::math::rq::Representation::PowerBasis);
        ci.drop_to_context(last_ctx);
        if (original_repr != ::bfv::math::rq::Representation::PowerBasis) {
          ci.change_representation(original_repr);
        }
      }
    }
  } catch (const std::exception &e) {
    throw MathException("Failed to switch to last level: " +
                        std::string(e.what()));
  }
}

void Ciphertext::mod_switch_to_next_level() {
  if (!pImpl->par) {
    throw MathException("Ciphertext has no parameters");
  }

  if (pImpl->level < pImpl->par->max_level()) {
    try {
      pImpl->seed = std::nullopt;  // Clear seed when modifying

      for (auto &ci : pImpl->c) {
        auto original_repr = ci.representation();
        ci.change_representation(::bfv::math::rq::Representation::PowerBasis);
        ci.drop_last_residue();
        if (original_repr != ::bfv::math::rq::Representation::PowerBasis) {
          ci.change_representation(original_repr);
        }
      }

      pImpl->level += 1;
    } catch (const std::exception &e) {
      throw MathException("Failed to switch to next level: " +
                          std::string(e.what()));
    }
  }
}

size_t Ciphertext::level() const { return pImpl->level; }

size_t Ciphertext::size() const { return pImpl->c.size(); }

bool Ciphertext::empty() const { return !pImpl->par || pImpl->c.empty(); }

std::shared_ptr<BfvParameters> Ciphertext::parameters() const {
  return pImpl->par;
}

// Access to internal polynomials
const ::bfv::math::rq::Poly &Ciphertext::polynomial(size_t index) const {
  if (index >= pImpl->c.size()) {
    throw std::out_of_range("Polynomial index " + std::to_string(index) +
                            " out of range [0, " +
                            std::to_string(pImpl->c.size()) + ")");
  }
  return pImpl->c[index];
}

const std::vector<::bfv::math::rq::Poly> &Ciphertext::polynomials() const {
  return pImpl->c;
}

// Seed management
bool Ciphertext::has_seed() const { return pImpl->seed.has_value(); }

std::optional<std::array<uint8_t, 32>> Ciphertext::seed() const {
  return pImpl->seed;
}

void Ciphertext::set_seed(const std::array<uint8_t, 32> &seed) {
  if (pImpl) {
    pImpl->seed = seed;
  }
}

// Internal methods
void Ciphertext::truncate(size_t len) {
  if (len < pImpl->c.size()) {
    pImpl->c.resize(len);
  }
}

// Serialization implementation
yacl::Buffer Ciphertext::Serialize() const {
  if (!pImpl || !pImpl->par) {
    throw ser::SerializationException("Ciphertext is not initialized");
  }

  CiphertextData data;
  data.level = pImpl->level;
  data.has_seed = pImpl->seed.has_value();
  if (data.has_seed) {
    const auto &seed = *pImpl->seed;
    data.seed.assign(seed.begin(), seed.end());
  }

  data.polynomials.reserve(pImpl->c.size());
  for (const auto &poly : pImpl->c) {
    data.polynomials.push_back(poly.to_bytes());
  }

  return MsgpackSerializer::Serialize(data);
}

void Ciphertext::Deserialize(yacl::ByteContainerView in,
                             std::shared_ptr<BfvParameters> params,
                             ::bfv::util::ArenaHandle pool) {
  *this = from_bytes(in, std::move(params), pool);
}

Ciphertext Ciphertext::from_bytes(yacl::ByteContainerView bytes,
                                  std::shared_ptr<BfvParameters> params,
                                  ::bfv::util::ArenaHandle pool) {
  if (!params) {
    throw ser::SerializationException("Parameters are required for Ciphertext");
  }

  try {
    auto data = MsgpackSerializer::Deserialize<CiphertextData>(bytes);
    if (data.polynomials.empty()) {
      auto zero = Ciphertext::zero(std::move(params), pool);
      if (data.has_seed) {
        throw ser::SerializationException(
            "Empty ciphertext payload cannot carry a seed");
      }
      return zero;
    }

    auto ctx = params->ctx_at_level(data.level);
    std::vector<::bfv::math::rq::Poly> polynomials;
    polynomials.reserve(data.polynomials.size());
    for (const auto &poly_bytes : data.polynomials) {
      polynomials.push_back(
          ::bfv::math::rq::Poly::from_bytes(poly_bytes, ctx, pool));
    }

    auto ciphertext = Ciphertext::from_polynomials_with_level(
        std::move(polynomials), params, data.level, pool);
    if (data.has_seed) {
      if (data.seed.size() != 32) {
        throw ser::SerializationException("Invalid ciphertext seed size");
      }
      std::array<uint8_t, 32> seed;
      std::copy(data.seed.begin(), data.seed.end(), seed.begin());
      ciphertext.set_seed(seed);
    }
    return ciphertext;
  } catch (const ser::SerializationException &) {
    throw;
  } catch (const std::exception &e) {
    throw ser::SerializationException("Failed to deserialize Ciphertext: " +
                                      std::string(e.what()));
  }
}

// Methods for relinearization support
::bfv::math::rq::Poly &Ciphertext::mutable_component(size_t index) {
  if (!pImpl) {
    throw ParameterException("Ciphertext is not initialized");
  }

  if (index >= pImpl->c.size()) {
    throw std::out_of_range("Component index out of range");
  }

  return pImpl->c[index];
}

void Ciphertext::add_to_component(size_t index,
                                  const ::bfv::math::rq::Poly &poly) {
  if (!pImpl) {
    throw ParameterException("Ciphertext is not initialized");
  }

  if (index >= pImpl->c.size()) {
    throw std::out_of_range("Component index out of range");
  }

  try {
    // Add the polynomial to the specified component
    pImpl->c[index] += poly;
  } catch (const std::exception &e) {
    throw MathException("Failed to add to ciphertext component: " +
                        std::string(e.what()));
  }
}

void Ciphertext::truncate_to_size(size_t new_size) {
  if (!pImpl) {
    throw ParameterException("Ciphertext is not initialized");
  }

  if (new_size == 0) {
    throw ParameterException("Cannot truncate to size 0");
  }

  if (new_size < pImpl->c.size()) {
    pImpl->c.resize(new_size);
  }
  // If new_size >= current size, do nothing (no expansion)
}

void Ciphertext::add_inplace(const Ciphertext &other) {
  if (!pImpl || !other.pImpl) {
    throw ParameterException("Ciphertext is not initialized");
  }

  if (!pImpl->par || !other.pImpl->par) {
    throw ParameterException("Ciphertext parameters are not set");
  }

  if (*pImpl->par != *other.pImpl->par) {
    throw ParameterException("Ciphertexts must have the same parameters");
  }

  if (pImpl->level != other.pImpl->level) {
    throw ParameterException("Ciphertexts must be at the same level");
  }
  if (!pImpl->c.empty() && !other.pImpl->c.empty() &&
      pImpl->c[0].representation() != other.pImpl->c[0].representation()) {
    throw ParameterException("Ciphertexts must have the same representation");
  }

  // Ensure this ciphertext has enough room
  if (pImpl->c.size() < other.pImpl->c.size()) {
    pImpl->c.resize(other.pImpl->c.size(),
                    ::bfv::math::rq::Poly::zero(pImpl->c[0].ctx(),
                                                pImpl->c[0].representation()));
  }

  // Add polynomials
  for (size_t i = 0; i < other.pImpl->c.size(); ++i) {
    pImpl->c[i] += other.pImpl->c[i];
  }

  // Clear seed as the ciphertext is modified
  pImpl->seed = std::nullopt;
}

void Ciphertext::sub_inplace(const Ciphertext &other) {
  if (!pImpl || !other.pImpl) {
    throw ParameterException("Ciphertext is not initialized");
  }

  if (!pImpl->par || !other.pImpl->par) {
    throw ParameterException("Ciphertext parameters are not set");
  }

  if (*pImpl->par != *other.pImpl->par) {
    throw ParameterException("Ciphertexts must have the same parameters");
  }

  if (pImpl->level != other.pImpl->level) {
    throw ParameterException("Ciphertexts must be at the same level");
  }
  if (!pImpl->c.empty() && !other.pImpl->c.empty() &&
      pImpl->c[0].representation() != other.pImpl->c[0].representation()) {
    throw ParameterException("Ciphertexts must have the same representation");
  }

  // Ensure this ciphertext has enough room
  if (pImpl->c.size() < other.pImpl->c.size()) {
    pImpl->c.resize(other.pImpl->c.size(),
                    ::bfv::math::rq::Poly::zero(pImpl->c[0].ctx(),
                                                pImpl->c[0].representation()));
  }

  // Subtract polynomials
  for (size_t i = 0; i < other.pImpl->c.size(); ++i) {
    pImpl->c[i] -= other.pImpl->c[i];
  }

  // Clear seed as the ciphertext is modified
  pImpl->seed = std::nullopt;
}

}  // namespace bfv
}  // namespace crypto
