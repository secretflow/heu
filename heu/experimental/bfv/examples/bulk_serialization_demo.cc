#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "heu/experimental/bfv/crypto/bfv_parameters.h"
#include "heu/experimental/bfv/crypto/bulk_serialization.h"
#include "heu/experimental/bfv/crypto/encoding.h"
#include "heu/experimental/bfv/crypto/evaluation_key.h"
#include "heu/experimental/bfv/crypto/galois_key.h"
#include "heu/experimental/bfv/crypto/key_switching_key.h"
#include "heu/experimental/bfv/crypto/multiplicator.h"
#include "heu/experimental/bfv/crypto/plaintext.h"
#include "heu/experimental/bfv/crypto/public_key.h"
#include "heu/experimental/bfv/crypto/relinearization_key.h"
#include "heu/experimental/bfv/crypto/secret_key.h"
#include "heu/experimental/bfv/crypto/serialization/serialization_exceptions.h"
#include "heu/experimental/bfv/math/poly.h"
#include "heu/experimental/bfv/math/representation.h"

using namespace crypto::bfv;
namespace ser = crypto::bfv::serialization;

namespace {

void Require(bool condition, const std::string &message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

void PrintVectorPrefix(const std::string &label,
                       const std::vector<uint64_t> &values,
                       size_t prefix_len = 8) {
  const size_t count = std::min(prefix_len, values.size());
  std::cout << label << ": [";
  for (size_t i = 0; i < count; ++i) {
    if (i != 0) {
      std::cout << ", ";
    }
    std::cout << values[i];
  }
  if (values.size() > count) {
    std::cout << ", ...";
  }
  std::cout << "]" << std::endl;
}

}  // namespace

int main() {
  std::cout << "=== BFV Bulk Serialization Demo ===\n" << std::endl;

  auto params = BfvParameters::default_arc(2, 16);
  std::mt19937_64 rng(42);
  auto secret_key = SecretKey::random(params, rng);
  auto public_key = PublicKey::from_secret_key(secret_key, rng);
  auto encoding = Encoding::poly();

  std::vector<std::vector<uint64_t>> raw_values = {
      {1, 2, 3, 4},
      {10, 20, 30, 40},
  };

  std::vector<Plaintext> plaintexts;
  std::vector<Ciphertext> ciphertexts;
  plaintexts.reserve(raw_values.size());
  ciphertexts.reserve(raw_values.size());
  for (const auto &values : raw_values) {
    auto plaintext = Plaintext::encode(values, encoding, params);
    ciphertexts.push_back(secret_key.encrypt(plaintext, rng));
    plaintexts.push_back(std::move(plaintext));
  }

  auto plaintext_bundle = BulkSerializer::SerializePlaintexts(plaintexts);
  auto ciphertext_bundle = BulkSerializer::SerializeCiphertexts(ciphertexts);
  auto eval_key_inner_sum =
      EvaluationKeyBuilder::create(secret_key).enable_inner_sum().build(rng);
  auto eval_key_rotation = EvaluationKeyBuilder::create(secret_key)
                               .enable_row_rotation()
                               .enable_column_rotation(1)
                               .build(rng);
  std::vector<EvaluationKey> evaluation_keys = {
      eval_key_inner_sum,
      eval_key_rotation,
  };
  std::vector<RelinearizationKey> relinearization_keys = {
      RelinearizationKey::from_secret_key(secret_key, rng),
      RelinearizationKey::from_secret_key(secret_key, rng),
  };
  auto evaluation_key_bundle =
      BulkSerializer::SerializeEvaluationKeys(evaluation_keys);
  auto relinearization_key_bundle =
      BulkSerializer::SerializeRelinearizationKeys(relinearization_keys);
  std::vector<SecretKey> secret_keys;
  secret_keys.emplace_back(
      SecretKey::from_coefficients(secret_key.coefficients(), params));
  auto secret_key_bundle = BulkSerializer::SerializeSecretKeys(secret_keys);
  auto public_key_bundle = BulkSerializer::SerializePublicKeys({public_key});
  auto galois_key = GaloisKey::create(secret_key, 9, 0, 0, rng);
  auto galois_key_bundle = BulkSerializer::SerializeGaloisKeys({galois_key});
  auto switching_poly = ::bfv::math::rq::Poly::small(
      params->ctx_at_level(0), ::bfv::math::rq::Representation::PowerBasis, 10,
      rng);
  auto key_switching_key =
      KeySwitchingKey::create(secret_key, switching_poly, 0, 0, rng);
  auto key_switching_key_bundle =
      BulkSerializer::SerializeKeySwitchingKeys({key_switching_key});

  std::cout << "Plaintext bundle bytes: " << plaintext_bundle.size()
            << std::endl;
  std::cout << "Ciphertext bundle bytes: " << ciphertext_bundle.size()
            << std::endl;
  std::cout << "Evaluation key bundle bytes: " << evaluation_key_bundle.size()
            << std::endl;
  std::cout << "Relinearization key bundle bytes: "
            << relinearization_key_bundle.size() << std::endl;
  std::cout << "Secret key bundle bytes: " << secret_key_bundle.size()
            << std::endl;
  std::cout << "Public key bundle bytes: " << public_key_bundle.size()
            << std::endl;
  std::cout << "Galois key bundle bytes: " << galois_key_bundle.size()
            << std::endl;
  std::cout << "Key-switching key bundle bytes: "
            << key_switching_key_bundle.size() << std::endl;

  auto restored_plaintexts =
      BulkSerializer::DeserializePlaintexts(plaintext_bundle);
  auto restored_ciphertexts = BulkSerializer::DeserializeCiphertexts(
      ciphertext_bundle, params, ::bfv::util::ArenaHandle::Shared());
  auto restored_evaluation_keys =
      BulkSerializer::DeserializeEvaluationKeys(evaluation_key_bundle, params);
  auto restored_relinearization_keys =
      BulkSerializer::DeserializeRelinearizationKeys(relinearization_key_bundle,
                                                     params);
  auto restored_secret_keys =
      BulkSerializer::DeserializeSecretKeys(secret_key_bundle, params);
  auto restored_public_keys =
      BulkSerializer::DeserializePublicKeys(public_key_bundle, params);
  auto restored_galois_keys =
      BulkSerializer::DeserializeGaloisKeys(galois_key_bundle, params);
  auto restored_key_switching_keys =
      BulkSerializer::DeserializeKeySwitchingKeys(key_switching_key_bundle,
                                                  params);

  Require(restored_plaintexts.items.size() == plaintexts.size(),
          "plaintext batch round-trip changed item count");
  Require(restored_ciphertexts.items.size() == ciphertexts.size(),
          "ciphertext batch round-trip changed item count");

  for (size_t i = 0; i < plaintexts.size(); ++i) {
    Require(restored_plaintexts.items[i] == plaintexts[i],
            "plaintext batch round-trip mismatch");

    auto expected = plaintexts[i].decode_uint64(encoding);
    auto recovered = secret_key.decrypt(restored_ciphertexts.items[i], encoding)
                         .decode_uint64(encoding);
    Require(recovered == expected, "ciphertext batch round-trip mismatch");
    PrintVectorPrefix("Recovered item " + std::to_string(i), recovered);
  }

  Require(restored_evaluation_keys.items.size() == evaluation_keys.size(),
          "evaluation key batch round-trip changed item count");
  Require(
      restored_relinearization_keys.items.size() == relinearization_keys.size(),
      "relinearization key batch round-trip changed item count");
  Require(restored_secret_keys.items.size() == 1,
          "secret key batch round-trip changed item count");
  Require(restored_public_keys.items.size() == 1,
          "public key batch round-trip changed item count");
  Require(restored_galois_keys.items.size() == 1,
          "galois key batch round-trip changed item count");
  Require(restored_key_switching_keys.items.size() == 1,
          "key-switching key batch round-trip changed item count");

  Require(restored_evaluation_keys.items[0].supports_inner_sum(),
          "restored evaluation key lost inner-sum support");
  Require(restored_evaluation_keys.items[1].supports_row_rotation() &&
              restored_evaluation_keys.items[1].supports_column_rotation_by(1),
          "restored evaluation key lost rotation support");

  auto simd_plaintext =
      Plaintext::encode(raw_values[0], Encoding::simd(), params);
  auto simd_ciphertext = secret_key.encrypt(simd_plaintext, rng);
  auto inner_sum_ciphertext =
      restored_evaluation_keys.items[0].computes_inner_sum(simd_ciphertext);
  auto inner_sum_values =
      secret_key.decrypt(inner_sum_ciphertext, Encoding::simd())
          .decode_uint64(Encoding::simd());
  PrintVectorPrefix("Inner-sum via restored evaluation key", inner_sum_values);

  auto multiplicator =
      Multiplicator::create_default(restored_relinearization_keys.items[0]);
  auto squared_ciphertext =
      multiplicator->multiply(simd_ciphertext, simd_ciphertext);
  auto squared_values = secret_key.decrypt(squared_ciphertext, Encoding::simd())
                            .decode_uint64(Encoding::simd());
  PrintVectorPrefix("Square via restored relin key", squared_values);

  auto reencrypted = restored_public_keys.items[0].encrypt(plaintexts[0], rng);
  auto reencrypted_values = restored_secret_keys.items[0]
                                .decrypt(reencrypted, encoding)
                                .decode_uint64(encoding);
  PrintVectorPrefix("Decrypt via restored secret/public keys",
                    reencrypted_values);

  auto galois_original =
      secret_key.decrypt(galois_key.apply(simd_ciphertext), Encoding::simd())
          .decode_uint64(Encoding::simd());
  auto galois_restored =
      secret_key
          .decrypt(restored_galois_keys.items[0].apply(simd_ciphertext),
                   Encoding::simd())
          .decode_uint64(Encoding::simd());
  Require(galois_original == galois_restored,
          "restored galois key changed automorphism result");
  PrintVectorPrefix("Automorphism via restored galois key", galois_restored);

  Require(restored_key_switching_keys.items[0] == key_switching_key,
          "restored key-switching key does not match the original");
  std::cout << "Restored key-switching key matches the original" << std::endl;

  try {
    auto mismatched_params = BfvParameters::default_arc(3, 32);
    (void)BulkSerializer::DeserializeCiphertexts(ciphertext_bundle,
                                                 mismatched_params);
    throw std::runtime_error("expected parameter mismatch was not raised");
  } catch (const ser::ParameterMismatchException &e) {
    std::cout << "Mismatch check: " << e.what() << std::endl;
  }

  return 0;
}
