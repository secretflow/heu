#pragma once

#include <memory>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/evaluation_key.h"
#include "crypto/galois_key.h"
#include "crypto/key_switching_key.h"
#include "crypto/plaintext.h"
#include "crypto/public_key.h"
#include "crypto/relinearization_key.h"
#include "crypto/secret_key.h"
#include "yacl/base/byte_container_view.h"

namespace crypto {
namespace bfv {

struct PlaintextBatch {
  std::shared_ptr<BfvParameters> params;
  std::vector<Plaintext> items;
};

struct CiphertextBatch {
  std::shared_ptr<BfvParameters> params;
  std::vector<Ciphertext> items;
};

struct EvaluationKeyBatch {
  std::shared_ptr<BfvParameters> params;
  std::vector<EvaluationKey> items;
};

struct RelinearizationKeyBatch {
  std::shared_ptr<BfvParameters> params;
  std::vector<RelinearizationKey> items;
};

struct SecretKeyBatch {
  std::shared_ptr<BfvParameters> params;
  std::vector<SecretKey> items;
};

struct PublicKeyBatch {
  std::shared_ptr<BfvParameters> params;
  std::vector<PublicKey> items;
};

struct GaloisKeyBatch {
  std::shared_ptr<BfvParameters> params;
  std::vector<GaloisKey> items;
};

struct KeySwitchingKeyBatch {
  std::shared_ptr<BfvParameters> params;
  std::vector<KeySwitchingKey> items;
};

// Batch-oriented serialization for integration paths that move many BFV objects
// with a shared parameter set. The bundle embeds the parameters once, records a
// schema version/type tag, and validates per-payload checksums on decode.
class BulkSerializer {
 public:
  static yacl::Buffer SerializePlaintexts(
      const std::vector<Plaintext> &plaintexts,
      std::shared_ptr<BfvParameters> params = nullptr);

  static PlaintextBatch DeserializePlaintexts(
      yacl::ByteContainerView in,
      std::shared_ptr<BfvParameters> expected_params = nullptr);

  static yacl::Buffer SerializeCiphertexts(
      const std::vector<Ciphertext> &ciphertexts,
      std::shared_ptr<BfvParameters> params = nullptr);

  static CiphertextBatch DeserializeCiphertexts(
      yacl::ByteContainerView in,
      std::shared_ptr<BfvParameters> expected_params = nullptr,
      ::bfv::util::ArenaHandle pool = ::bfv::util::ArenaHandle::Shared());

  static yacl::Buffer SerializeEvaluationKeys(
      const std::vector<EvaluationKey> &evaluation_keys,
      std::shared_ptr<BfvParameters> params = nullptr);

  static EvaluationKeyBatch DeserializeEvaluationKeys(
      yacl::ByteContainerView in,
      std::shared_ptr<BfvParameters> expected_params = nullptr);

  static yacl::Buffer SerializeRelinearizationKeys(
      const std::vector<RelinearizationKey> &relinearization_keys,
      std::shared_ptr<BfvParameters> params = nullptr);

  static RelinearizationKeyBatch DeserializeRelinearizationKeys(
      yacl::ByteContainerView in,
      std::shared_ptr<BfvParameters> expected_params = nullptr);

  static yacl::Buffer SerializeSecretKeys(
      const std::vector<SecretKey> &secret_keys,
      std::shared_ptr<BfvParameters> params = nullptr);

  static SecretKeyBatch DeserializeSecretKeys(
      yacl::ByteContainerView in,
      std::shared_ptr<BfvParameters> expected_params = nullptr);

  static yacl::Buffer SerializePublicKeys(
      const std::vector<PublicKey> &public_keys,
      std::shared_ptr<BfvParameters> params = nullptr);

  static PublicKeyBatch DeserializePublicKeys(
      yacl::ByteContainerView in,
      std::shared_ptr<BfvParameters> expected_params = nullptr);

  static yacl::Buffer SerializeGaloisKeys(
      const std::vector<GaloisKey> &galois_keys,
      std::shared_ptr<BfvParameters> params = nullptr);

  static GaloisKeyBatch DeserializeGaloisKeys(
      yacl::ByteContainerView in,
      std::shared_ptr<BfvParameters> expected_params = nullptr);

  static yacl::Buffer SerializeKeySwitchingKeys(
      const std::vector<KeySwitchingKey> &key_switching_keys,
      std::shared_ptr<BfvParameters> params = nullptr);

  static KeySwitchingKeyBatch DeserializeKeySwitchingKeys(
      yacl::ByteContainerView in,
      std::shared_ptr<BfvParameters> expected_params = nullptr);
};

}  // namespace bfv
}  // namespace crypto
