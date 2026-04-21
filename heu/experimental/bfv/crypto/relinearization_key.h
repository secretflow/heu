#pragma once

#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include "crypto/exceptions.h"
#include "yacl/base/byte_container_view.h"

// Forward declarations for math components
namespace bfv {
namespace math {
namespace rq {
class Poly;
enum class Representation;
}  // namespace rq
}  // namespace math
}  // namespace bfv

// Forward declarations for BFV components
namespace crypto {
namespace bfv {
class BfvParameters;
class Ciphertext;
class SecretKey;
class KeySwitchingKey;
}  // namespace bfv
}  // namespace crypto

namespace crypto {
namespace bfv {

/**
 * Relinearization key for the BFV encryption scheme.
 *
 * A relinearization key is a special type of key switching key,
 * which switches from s^2 to s where s is the secret key.
 * This allows reducing degree-2 ciphertexts (result of multiplication)
 * back to degree-1 ciphertexts.
 */
class RelinearizationKey {
 public:
  // Destructor
  ~RelinearizationKey();

  // Copy constructor and assignment
  RelinearizationKey(const RelinearizationKey &other);
  RelinearizationKey &operator=(const RelinearizationKey &other);

  // Move constructor and assignment
  RelinearizationKey(RelinearizationKey &&other) noexcept;
  RelinearizationKey &operator=(RelinearizationKey &&other) noexcept;

  // Static factory methods for key generation
  /**
   * @brief Generate a new RelinearizationKey from a SecretKey
   * @tparam RNG Random number generator type (must satisfy CryptoRng
   * requirements)
   * @param secret_key The secret key to generate from
   * @param rng Random number generator
   * @return Generated relinearization key
   * @throws ParameterException if secret key is invalid or parameters don't
   * support key switching
   * @throws MathException if generation fails
   */
  template <typename RNG>
  static RelinearizationKey from_secret_key(const SecretKey &secret_key,
                                            RNG &rng);

  /**
   * @brief Generate a new RelinearizationKey from a SecretKey using
   * std::mt19937_64
   * @param secret_key The secret key to generate from
   * @param rng Random number generator
   * @return Generated relinearization key
   * @throws ParameterException if secret key is invalid or parameters don't
   * support key switching
   * @throws MathException if generation fails
   */
  static RelinearizationKey from_secret_key(const SecretKey &secret_key,
                                            std::mt19937_64 &rng);

  /**
   * @brief Generate a leveled RelinearizationKey from a SecretKey
   * @tparam RNG Random number generator type
   * @param secret_key The secret key to generate from
   * @param ciphertext_level The level of ciphertexts to be relinearized
   * @param key_level The level of the relinearization key
   * @param rng Random number generator
   * @return Generated relinearization key
   * @throws ParameterException if parameters are invalid
   * @throws MathException if generation fails
   */
  template <typename RNG>
  static RelinearizationKey from_secret_key_leveled(const SecretKey &secret_key,
                                                    size_t ciphertext_level,
                                                    size_t key_level, RNG &rng);

  /**
   * @brief Generate a leveled RelinearizationKey from a SecretKey using
   * std::mt19937_64
   * @param secret_key The secret key to generate from
   * @param ciphertext_level The level of ciphertexts to be relinearized
   * @param key_level The level of the relinearization key
   * @param rng Random number generator
   * @return Generated relinearization key
   * @throws ParameterException if parameters are invalid
   * @throws MathException if generation fails
   */
  static RelinearizationKey from_secret_key_leveled(const SecretKey &secret_key,
                                                    size_t ciphertext_level,
                                                    size_t key_level,
                                                    std::mt19937_64 &rng);

  // Relinearization methods
  /**
   * @brief Relinearize a degree-2 ciphertext to degree-1 (in-place)
   * @param ciphertext The degree-2 ciphertext to relinearize (modified
   * in-place)
   * @throws ParameterException if parameters don't match or ciphertext is not
   * degree-2
   * @throws MathException if relinearization fails
   */
  void relinearize(Ciphertext &ciphertext) const;

  /**
   * @brief Relinearize a degree-2 ciphertext to degree-1 (returns new
   * ciphertext)
   * @param ciphertext The degree-2 ciphertext to relinearize
   * @return Relinearized degree-1 ciphertext
   * @throws ParameterException if parameters don't match or ciphertext is not
   * degree-2
   * @throws MathException if relinearization fails
   */
  Ciphertext relinearize_new(const Ciphertext &ciphertext) const;

  /**
   * @brief Relinearize using polynomials (internal method)
   * @param c2 The c2 polynomial from a degree-2 ciphertext
   * @return Pair of polynomials (c0_delta, c1_delta) to add to the original c0
   * and c1
   * @throws MathException if relinearization fails
   */
  std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly> relinearize_poly(
      const ::bfv::math::rq::Poly &c2) const;
  std::pair<::bfv::math::rq::Poly, ::bfv::math::rq::Poly> relinearize_poly(
      const ::bfv::math::rq::Poly &c2,
      ::bfv::math::rq::Representation output_representation) const;
  void relinearize_poly(
      const ::bfv::math::rq::Poly &c2, ::bfv::math::rq::Poly &c0_delta,
      ::bfv::math::rq::Poly &c1_delta,
      ::bfv::math::rq::Representation output_representation) const;

  // Accessors
  /**
   * @brief Get the BFV parameters
   * @return Shared pointer to parameters
   */
  std::shared_ptr<BfvParameters> parameters() const;

  /**
   * @brief Check if this relinearization key is empty/uninitialized
   * @return true if empty, false otherwise
   */
  bool empty() const;

  /**
   * @brief Get the ciphertext level this key can relinearize
   * @return Ciphertext level
   */
  size_t ciphertext_level() const;

  /**
   * @brief Get the key level of this relinearization key
   * @return Key level
   */
  size_t key_level() const;

  /**
   * @brief Get access to the underlying key switching key (for advanced use)
   * @return Reference to the key switching key
   */
  const KeySwitchingKey &key_switching_key() const;

  // Equality operators
  bool operator==(const RelinearizationKey &other) const;
  bool operator!=(const RelinearizationKey &other) const;

  // Serialization methods
  /**
   * @brief Serialize relinearization key to bytes using msgpack
   * @return Serialized relinearization key data as yacl::Buffer
   * @throws SerializationException if serialization fails
   */
  [[nodiscard]] yacl::Buffer Serialize() const;

  /**
   * @brief Deserialize relinearization key from bytes
   * @param in Serialized relinearization key data
   * @param params BFV parameters for reconstruction
   * @throws SerializationException if deserialization fails
   */
  void Deserialize(yacl::ByteContainerView in,
                   std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create relinearization key from serialized bytes
   * @param bytes Serialized relinearization key data
   * @param params BFV parameters for reconstruction
   * @return Deserialized relinearization key
   * @throws SerializationException if deserialization fails
   */
  static RelinearizationKey from_bytes(yacl::ByteContainerView bytes,
                                       std::shared_ptr<BfvParameters> params);

  /**
   * @brief Create RelinearizationKey from KeySwitchingKey (for deserialization)
   * @param ksk Key switching key
   * @param params BFV parameters
   * @return RelinearizationKey constructed from key switching key
   */
  static RelinearizationKey from_key_switching_key(
      KeySwitchingKey ksk, std::shared_ptr<BfvParameters> params);

 private:
  // PIMPL idiom
  class Impl;
  std::unique_ptr<Impl> impl_;

  // Private constructor for internal use
  explicit RelinearizationKey(std::unique_ptr<Impl> impl);

  // Internal implementation method
  static RelinearizationKey from_secret_key_leveled_internal(
      const SecretKey &secret_key, size_t ciphertext_level, size_t key_level,
      std::mt19937_64 &rng);

  // Friend classes that need access to internal methods
  friend class EvaluationKey;
  friend class GaloisKey;
};

}  // namespace bfv
}  // namespace crypto

// Include template implementations
#include "crypto/relinearization_key_impl.h"
