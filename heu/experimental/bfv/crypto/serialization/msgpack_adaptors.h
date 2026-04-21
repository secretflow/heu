// Copyright 2024 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "msgpack.hpp"
#include "yacl/base/byte_container_view.h"

namespace crypto {
namespace bfv {

// Forward declarations
class BfvParameters;
class SecretKey;
class PublicKey;
class Plaintext;
class Ciphertext;
class RelinearizationKey;
class GaloisKey;
class EvaluationKey;
class KeySwitchingKey;
class RGSWCiphertext;

/**
 * @brief Serialization data structure for BfvParameters
 *
 * This structure holds the minimal data needed to reconstruct BfvParameters.
 * Other computed values (contexts, NTT operators, etc.) are recomputed on
 * deserialization.
 */
struct BfvParametersData {
  size_t polynomial_degree;
  uint64_t plaintext_modulus;
  std::vector<uint64_t> moduli;
  std::vector<size_t> moduli_sizes;
  size_t variance;

  MSGPACK_DEFINE(polynomial_degree, plaintext_modulus, moduli, moduli_sizes,
                 variance);
};

/**
 * @brief Serialization data structure for SecretKey
 */
struct SecretKeyData {
  std::vector<int64_t> coeffs;
  BfvParametersData params;

  MSGPACK_DEFINE(coeffs, params);
};

/**
 * @brief Serialization data structure for PublicKey
 *
 * Stores the two polynomial components (c0, c1) of the public key.
 */
struct PublicKeyData {
  std::vector<uint8_t> ciphertext;

  MSGPACK_DEFINE(ciphertext);
};

/**
 * @brief Serialization data structure for Plaintext
 */
struct PlaintextData {
  std::vector<uint64_t> coeffs;
  size_t level;
  bool has_encoding;
  int encoding_type;

  MSGPACK_DEFINE(coeffs, level, has_encoding, encoding_type);
};

/**
 * @brief Serialization data structure for Ciphertext
 *
 * Stores the polynomial components of the ciphertext.
 */
struct CiphertextData {
  std::vector<std::vector<uint8_t>> polynomials;
  size_t level;
  bool has_seed;
  std::vector<uint8_t> seed;

  MSGPACK_DEFINE(polynomials, level, has_seed, seed);
};

/**
 * @brief Serialization data structure for KeySwitchingKey
 */
struct KeySwitchingKeyData {
  std::vector<std::vector<uint8_t>> c0_polys;
  std::vector<std::vector<uint8_t>> c1_polys;
  size_t ciphertext_level;
  size_t ksk_level;
  size_t log_base;
  bool has_seed;
  std::vector<uint8_t> seed;
  BfvParametersData params;

  MSGPACK_DEFINE(c0_polys, c1_polys, ciphertext_level, ksk_level, log_base,
                 has_seed, seed, params);
};

/**
 * @brief Serialization data structure for RelinearizationKey
 */
struct RelinearizationKeyData {
  std::vector<uint8_t> key_switching_key;

  MSGPACK_DEFINE(key_switching_key);
};

/**
 * @brief Serialization data structure for GaloisKey
 */
struct GaloisKeyData {
  size_t exponent;
  std::vector<uint8_t> key_switching_key;

  MSGPACK_DEFINE(exponent, key_switching_key);
};

/**
 * @brief Serialization data structure for EvaluationKey
 */
struct EvaluationKeyData {
  size_t ciphertext_level;
  size_t evaluation_key_level;
  std::vector<std::pair<size_t, std::vector<uint8_t>>> galois_keys;

  MSGPACK_DEFINE(ciphertext_level, evaluation_key_level, galois_keys);
};

/**
 * @brief Serialization data structure for RGSWCiphertext
 */
struct RGSWCiphertextData {
  std::vector<uint8_t> ksk0;
  std::vector<uint8_t> ksk1;

  MSGPACK_DEFINE(ksk0, ksk1);
};

/**
 * @brief Utility functions for msgpack serialization
 */
class MsgpackSerializer {
 public:
  /**
   * @brief Serialize an object to yacl::Buffer using msgpack
   */
  template <typename T>
  static yacl::Buffer Serialize(const T &obj) {
    msgpack::sbuffer buffer;
    msgpack::pack(buffer, obj);
    auto sz = buffer.size();
    return {buffer.release(), sz, [](void *ptr) { free(ptr); }};
  }

  /**
   * @brief Deserialize an object from yacl::ByteContainerView using msgpack
   */
  template <typename T>
  static T Deserialize(yacl::ByteContainerView in) {
    auto msg =
        msgpack::unpack(reinterpret_cast<const char *>(in.data()), in.size());
    return msg.get().as<T>();
  }
};

}  // namespace bfv
}  // namespace crypto
