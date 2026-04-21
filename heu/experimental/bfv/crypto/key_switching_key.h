#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <vector>

#include "crypto/exceptions.h"
#include "math/representation.h"
#include "yacl/base/byte_container_view.h"

// Forward declarations for BFV components
namespace crypto {
namespace bfv {
class BfvParameters;
class SecretKey;
}  // namespace bfv
}  // namespace crypto

// Forward declarations for math library components
namespace bfv::math::rq {
class Poly;
class Context;
}  // namespace bfv::math::rq

namespace crypto {
namespace bfv {

/**
 * Key switching key for the BFV encryption scheme.
 *
 * This class represents a key switching key used for switching between
 * different secret keys in homomorphic operations. It enables operations like
 * relinearization and Galois transformations.
 */
class KeySwitchingKey {
 public:
  // Destructor
  ~KeySwitchingKey();

  // Copy constructor and assignment
  KeySwitchingKey(const KeySwitchingKey &other);
  KeySwitchingKey &operator=(const KeySwitchingKey &other);

  // Move constructor and assignment
  KeySwitchingKey(KeySwitchingKey &&other) noexcept;
  KeySwitchingKey &operator=(KeySwitchingKey &&other) noexcept;

  // Static factory methods for key generation
  /**
   * @brief Generate a KeySwitchingKey from a polynomial
   * @tparam RNG Random number generator type (must satisfy CryptoRng
   * requirements)
   * @param secret_key The secret key to switch to
   * @param from The polynomial to switch from
   * @param ciphertext_level The level of the ciphertext that will be key
   * switched
   * @param ksk_level The level of the key switching key
   * @param rng Random number generator
   * @return Generated key switching key
   * @throws ParameterException if parameters are invalid
   * @throws MathException if generation fails
   */
  template <typename RNG>
  static KeySwitchingKey create(const SecretKey &secret_key,
                                const ::bfv::math::rq::Poly &from,
                                size_t ciphertext_level, size_t ksk_level,
                                RNG &rng);

  /**
   * @brief Generate a KeySwitchingKey using std::mt19937_64
   * @param secret_key The secret key to switch to
   * @param from The polynomial to switch from
   * @param ciphertext_level The level of the ciphertext that will be key
   * switched
   * @param ksk_level The level of the key switching key
   * @param rng Random number generator
   * @return Generated key switching key
   * @throws ParameterException if parameters are invalid
   * @throws MathException if generation fails
   */
  static KeySwitchingKey create(const SecretKey &secret_key,
                                const ::bfv::math::rq::Poly &from,
                                size_t ciphertext_level, size_t ksk_level,
                                std::mt19937_64 &rng);

  // Key switching operations
  /**
   * @brief Perform key switching on a polynomial
   * @param poly The polynomial to key switch
   * @return Pair of polynomials (c0, c1) after key switching
   * @throws ParameterException if polynomial context doesn't match
   * @throws MathException if key switching fails
   */
  std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly> key_switch(
      const ::bfv::math::rq::Poly &poly) const;
  std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly> key_switch(
      const ::bfv::math::rq::Poly &poly,
      ::bfv::math::rq::Representation output_representation) const;

  // Accessors
  /**
   * @brief Get the BFV parameters
   * @return Shared pointer to parameters
   */
  std::shared_ptr<BfvParameters> parameters() const;

  /**
   * @brief Check if this key switching key is empty/uninitialized
   * @return true if empty, false otherwise
   */
  bool empty() const;

  /**
   * @brief Get the ciphertext level
   * @return The ciphertext level
   */
  size_t ciphertext_level() const;

  /**
   * @brief Get the key switching key level
   * @return The key switching key level
   */
  size_t ksk_level() const;

  /**
   * @brief Get the log base (for decomposition method)
   * @return The log base value
   */
  size_t log_base() const;

  /**
   * @brief Get the seed (if available)
   * @return Optional seed array
   */
  std::optional<std::array<uint8_t, 32>> seed() const;

  /**
   * @brief Get the c0 polynomial vector
   * @return Reference to the c0 polynomial vector
   */
  const std::vector<::bfv::math::rq::Poly> &c0_polynomials() const;

  /**
   * @brief Get the c1 polynomial vector
   * @return Reference to the c1 polynomial vector
   */
  const std::vector<::bfv::math::rq::Poly> &c1_polynomials() const;

  // Equality operators
  bool operator==(const KeySwitchingKey &other) const;
  bool operator!=(const KeySwitchingKey &other) const;

  // Arithmetic operators
  /**
   * @brief Add two key switching keys
   * @param other The other key switching key to add
   * @return The sum of the two key switching keys
   * @throws ParameterException if parameters don't match
   */
  KeySwitchingKey operator+(const KeySwitchingKey &other) const;

  // Serialization methods
  /**
   * @brief Serialize key switching key to bytes using msgpack
   * @return Serialized key switching key data as yacl::Buffer
   * @throws SerializationException if serialization fails
   */
  [[nodiscard]] yacl::Buffer Serialize() const;

  /**
   * @brief Deserialize key switching key from bytes
   * @param in Serialized key switching key data
   * @param params BFV parameters for reconstruction
   * @throws SerializationException if deserialization fails
   */
  void Deserialize(yacl::ByteContainerView in,
                   std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create key switching key from serialized bytes
   * @param bytes Serialized key switching key data
   * @param params BFV parameters for reconstruction
   * @return Deserialized key switching key
   * @throws SerializationException if deserialization fails
   */
  static KeySwitchingKey from_bytes(yacl::ByteContainerView bytes,
                                    std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create KeySwitchingKey from components (for deserialization)
   * @param params BFV parameters
   * @param seed Optional seed
   * @param c0_polys C0 polynomial vector
   * @param c1_polys C1 polynomial vector
   * @param ciphertext_level Ciphertext level
   * @param ksk_level Key switching key level
   * @param log_base Log base value
   * @return KeySwitchingKey constructed from components
   */
  static KeySwitchingKey from_components(
      std::shared_ptr<BfvParameters> params,
      std::optional<std::array<uint8_t, 32>> seed,
      std::vector<::bfv::math::rq::Poly> c0_polys,
      std::vector<::bfv::math::rq::Poly> c1_polys, size_t ciphertext_level,
      size_t ksk_level, size_t log_base);

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> pImpl;

  // Private constructor for internal use
  explicit KeySwitchingKey(std::unique_ptr<Impl> impl);

  // Internal implementation methods
  template <typename RNG>
  static KeySwitchingKey create_with_std_rng_bridge(
      const SecretKey &secret_key, const ::bfv::math::rq::Poly &from,
      size_t ciphertext_level, size_t ksk_level, RNG &rng);

  // Helper methods for key generation
  static std::vector<::bfv::math::rq::Poly> sample_c1_terms(
      std::shared_ptr<::bfv::math::rq::Context> ctx,
      const std::array<uint8_t, 32> &seed, size_t size, bool with_shoup);

  static std::vector<::bfv::math::rq::Poly> build_c0_terms(
      const SecretKey &secret_key, const ::bfv::math::rq::Poly &from,
      const std::vector<::bfv::math::rq::Poly> &c1, std::mt19937_64 &rng);

  static std::vector<::bfv::math::rq::Poly> build_c0_terms_decomposed(
      const SecretKey &secret_key, const ::bfv::math::rq::Poly &from,
      const std::vector<::bfv::math::rq::Poly> &c1, std::mt19937_64 &rng,
      size_t log_base);

  // Key switching implementation methods
  std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly> key_switch_decomposed(
      const ::bfv::math::rq::Poly &poly) const;
  std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly> key_switch_decomposed(
      const ::bfv::math::rq::Poly &poly,
      ::bfv::math::rq::Representation output_representation) const;
  void apply_key_switch_into(
      const ::bfv::math::rq::Poly &poly, ::bfv::math::rq::Poly &out_c0,
      ::bfv::math::rq::Poly &out_c1,
      ::bfv::math::rq::Representation output_representation) const;

  // Friend classes that need access to internal methods
  friend class RelinearizationKey;
  friend class EvaluationKey;
  friend class GaloisKey;
};

}  // namespace bfv
}  // namespace crypto

// Include template implementations
#include "crypto/key_switching_key_impl.h"
