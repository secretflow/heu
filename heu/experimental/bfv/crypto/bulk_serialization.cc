#include "crypto/bulk_serialization.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "crypto/serialization/msgpack_adaptors.h"
#include "crypto/serialization/serialization_exceptions.h"

namespace crypto {
namespace bfv {

namespace ser = serialization;

namespace {

constexpr uint32_t kBulkBundleVersion = 1;
constexpr uint64_t kFnv1a64OffsetBasis = 14695981039346656037ull;
constexpr uint64_t kFnv1a64Prime = 1099511628211ull;

enum class BundleObjectType : uint32_t {
  kPlaintext = 1,
  kCiphertext = 2,
  kEvaluationKey = 3,
  kRelinearizationKey = 4,
  kSecretKey = 5,
  kPublicKey = 6,
  kGaloisKey = 7,
  kKeySwitchingKey = 8,
};

struct BundleEntryData {
  std::vector<uint8_t> payload;
  uint64_t checksum = 0;

  MSGPACK_DEFINE(payload, checksum);
};

struct BundleData {
  uint32_t version = kBulkBundleVersion;
  uint32_t object_type = 0;
  std::vector<uint8_t> params;
  uint64_t params_checksum = 0;
  std::vector<BundleEntryData> payloads;

  MSGPACK_DEFINE(version, object_type, params, params_checksum, payloads);
};

uint64_t Fnv1a64(yacl::ByteContainerView in) {
  uint64_t hash = kFnv1a64OffsetBasis;
  for (uint8_t byte : in) {
    hash ^= static_cast<uint64_t>(byte);
    hash *= kFnv1a64Prime;
  }
  return hash;
}

std::vector<uint8_t> ToByteVector(const yacl::Buffer &buffer) {
  return std::vector<uint8_t>(buffer.data<uint8_t>(),
                              buffer.data<uint8_t>() + buffer.size());
}

const char *ObjectLabel(BundleObjectType type) {
  switch (type) {
    case BundleObjectType::kPlaintext:
      return "plaintext";
    case BundleObjectType::kCiphertext:
      return "ciphertext";
    case BundleObjectType::kEvaluationKey:
      return "evaluation key";
    case BundleObjectType::kRelinearizationKey:
      return "relinearization key";
    case BundleObjectType::kSecretKey:
      return "secret key";
    case BundleObjectType::kPublicKey:
      return "public key";
    case BundleObjectType::kGaloisKey:
      return "galois key";
    case BundleObjectType::kKeySwitchingKey:
      return "key switching key";
  }
  return "unknown";
}

void ValidateBundleMetadata(const BundleData &data, BundleObjectType expected) {
  if (data.version != kBulkBundleVersion) {
    throw ser::VersionMismatchException(kBulkBundleVersion, data.version);
  }

  if (data.object_type != static_cast<uint32_t>(expected)) {
    throw ser::SchemaValidationException(
        "Bundle object type mismatch: expected " +
        std::string(ObjectLabel(expected)) + ", got " +
        std::to_string(data.object_type));
  }
}

BundleData ParseBundle(yacl::ByteContainerView in, BundleObjectType expected) {
  try {
    auto data = MsgpackSerializer::Deserialize<BundleData>(in);
    ValidateBundleMetadata(data, expected);
    if (data.params.empty()) {
      throw ser::DataCorruptionException(
          "Bulk serialization bundle is missing embedded parameters");
    }
    return data;
  } catch (const ser::SerializationException &) {
    throw;
  } catch (const std::exception &e) {
    throw ser::SerializationException("Failed to deserialize " +
                                      std::string(ObjectLabel(expected)) +
                                      " batch: " + e.what());
  }
}

std::shared_ptr<BfvParameters> ResolveParametersForDeserialize(
    const BundleData &data, std::shared_ptr<BfvParameters> expected_params,
    BundleObjectType expected_type) {
  if (Fnv1a64(data.params) != data.params_checksum) {
    throw ser::DataCorruptionException(
        "Embedded BFV parameters checksum mismatch in " +
        std::string(ObjectLabel(expected_type)) + " batch");
  }

  auto embedded_params = BfvParameters::from_bytes(data.params);
  if (!expected_params) {
    return embedded_params;
  }

  if (*embedded_params != *expected_params) {
    throw ser::ParameterMismatchException(
        "Provided BFV parameters do not match the embedded batch parameters");
  }
  return expected_params;
}

template <typename Item>
std::shared_ptr<BfvParameters> ResolveParametersForSerialize(
    const std::vector<Item> &items,
    std::shared_ptr<BfvParameters> explicit_params, BundleObjectType type) {
  std::shared_ptr<BfvParameters> resolved = std::move(explicit_params);
  if (!resolved) {
    if (items.empty()) {
      throw ser::SerializationException(
          "Parameters are required when serializing an empty " +
          std::string(ObjectLabel(type)) + " batch");
    }
    resolved = items.front().parameters();
  }

  if (!resolved) {
    throw ser::SerializationException("Cannot serialize a " +
                                      std::string(ObjectLabel(type)) +
                                      " batch with null BFV parameters");
  }

  for (const auto &item : items) {
    auto item_params = item.parameters();
    if (!item_params) {
      throw ser::SerializationException("Cannot serialize an uninitialized " +
                                        std::string(ObjectLabel(type)) +
                                        " in a batch");
    }
    if (*item_params != *resolved) {
      throw ser::ParameterMismatchException(
          "All objects in a bulk serialization bundle must share the same BFV "
          "parameters");
    }
  }

  return resolved;
}

template <typename Item>
std::vector<BundleEntryData> SerializeEntries(const std::vector<Item> &items) {
  std::vector<BundleEntryData> entries;
  entries.reserve(items.size());
  for (const auto &item : items) {
    auto serialized = item.Serialize();
    entries.push_back(
        BundleEntryData{ToByteVector(serialized), Fnv1a64(serialized)});
  }
  return entries;
}

template <typename Result, typename Factory>
Result DeserializeEntries(const BundleData &data,
                          std::shared_ptr<BfvParameters> params,
                          Factory &&factory) {
  Result result;
  result.params = std::move(params);
  result.items.reserve(data.payloads.size());

  for (size_t idx = 0; idx < data.payloads.size(); ++idx) {
    const auto &entry = data.payloads[idx];
    if (entry.payload.empty()) {
      throw ser::DataCorruptionException(
          "Encountered an empty payload at bundle index " +
          std::to_string(idx));
    }
    if (Fnv1a64(entry.payload) != entry.checksum) {
      throw ser::DataCorruptionException(
          "Payload checksum mismatch at bundle index " + std::to_string(idx));
    }
    result.items.push_back(factory(entry.payload, result.params));
  }

  return result;
}

BundleData BuildBundle(BundleObjectType type,
                       const std::shared_ptr<BfvParameters> &params) {
  BundleData data;
  data.object_type = static_cast<uint32_t>(type);
  auto serialized_params = params->Serialize();
  data.params = ToByteVector(serialized_params);
  data.params_checksum = Fnv1a64(serialized_params);
  return data;
}

}  // namespace

yacl::Buffer BulkSerializer::SerializePlaintexts(
    const std::vector<Plaintext> &plaintexts,
    std::shared_ptr<BfvParameters> params) {
  auto resolved_params = ResolveParametersForSerialize(
      plaintexts, std::move(params), BundleObjectType::kPlaintext);
  auto data = BuildBundle(BundleObjectType::kPlaintext, resolved_params);
  data.payloads = SerializeEntries(plaintexts);
  return MsgpackSerializer::Serialize(data);
}

PlaintextBatch BulkSerializer::DeserializePlaintexts(
    yacl::ByteContainerView in,
    std::shared_ptr<BfvParameters> expected_params) {
  auto data = ParseBundle(in, BundleObjectType::kPlaintext);
  auto params = ResolveParametersForDeserialize(
      data, std::move(expected_params), BundleObjectType::kPlaintext);
  return DeserializeEntries<PlaintextBatch>(
      data, std::move(params),
      [](yacl::ByteContainerView payload,
         const std::shared_ptr<BfvParameters> &params) {
        return Plaintext::from_bytes(payload, params);
      });
}

yacl::Buffer BulkSerializer::SerializeCiphertexts(
    const std::vector<Ciphertext> &ciphertexts,
    std::shared_ptr<BfvParameters> params) {
  auto resolved_params = ResolveParametersForSerialize(
      ciphertexts, std::move(params), BundleObjectType::kCiphertext);
  auto data = BuildBundle(BundleObjectType::kCiphertext, resolved_params);
  data.payloads = SerializeEntries(ciphertexts);
  return MsgpackSerializer::Serialize(data);
}

CiphertextBatch BulkSerializer::DeserializeCiphertexts(
    yacl::ByteContainerView in, std::shared_ptr<BfvParameters> expected_params,
    ::bfv::util::ArenaHandle pool) {
  auto data = ParseBundle(in, BundleObjectType::kCiphertext);
  auto params = ResolveParametersForDeserialize(
      data, std::move(expected_params), BundleObjectType::kCiphertext);
  return DeserializeEntries<CiphertextBatch>(
      data, std::move(params),
      [pool](yacl::ByteContainerView payload,
             const std::shared_ptr<BfvParameters> &params) {
        return Ciphertext::from_bytes(payload, params, pool);
      });
}

yacl::Buffer BulkSerializer::SerializeEvaluationKeys(
    const std::vector<EvaluationKey> &evaluation_keys,
    std::shared_ptr<BfvParameters> params) {
  auto resolved_params = ResolveParametersForSerialize(
      evaluation_keys, std::move(params), BundleObjectType::kEvaluationKey);
  auto data = BuildBundle(BundleObjectType::kEvaluationKey, resolved_params);
  data.payloads = SerializeEntries(evaluation_keys);
  return MsgpackSerializer::Serialize(data);
}

EvaluationKeyBatch BulkSerializer::DeserializeEvaluationKeys(
    yacl::ByteContainerView in,
    std::shared_ptr<BfvParameters> expected_params) {
  auto data = ParseBundle(in, BundleObjectType::kEvaluationKey);
  auto params = ResolveParametersForDeserialize(
      data, std::move(expected_params), BundleObjectType::kEvaluationKey);
  return DeserializeEntries<EvaluationKeyBatch>(
      data, std::move(params),
      [](yacl::ByteContainerView payload,
         const std::shared_ptr<BfvParameters> &params) {
        return EvaluationKey::from_bytes(payload, params);
      });
}

yacl::Buffer BulkSerializer::SerializeRelinearizationKeys(
    const std::vector<RelinearizationKey> &relinearization_keys,
    std::shared_ptr<BfvParameters> params) {
  auto resolved_params =
      ResolveParametersForSerialize(relinearization_keys, std::move(params),
                                    BundleObjectType::kRelinearizationKey);
  auto data =
      BuildBundle(BundleObjectType::kRelinearizationKey, resolved_params);
  data.payloads = SerializeEntries(relinearization_keys);
  return MsgpackSerializer::Serialize(data);
}

RelinearizationKeyBatch BulkSerializer::DeserializeRelinearizationKeys(
    yacl::ByteContainerView in,
    std::shared_ptr<BfvParameters> expected_params) {
  auto data = ParseBundle(in, BundleObjectType::kRelinearizationKey);
  auto params = ResolveParametersForDeserialize(
      data, std::move(expected_params), BundleObjectType::kRelinearizationKey);
  return DeserializeEntries<RelinearizationKeyBatch>(
      data, std::move(params),
      [](yacl::ByteContainerView payload,
         const std::shared_ptr<BfvParameters> &params) {
        return RelinearizationKey::from_bytes(payload, params);
      });
}

yacl::Buffer BulkSerializer::SerializeSecretKeys(
    const std::vector<SecretKey> &secret_keys,
    std::shared_ptr<BfvParameters> params) {
  auto resolved_params = ResolveParametersForSerialize(
      secret_keys, std::move(params), BundleObjectType::kSecretKey);
  auto data = BuildBundle(BundleObjectType::kSecretKey, resolved_params);
  data.payloads = SerializeEntries(secret_keys);
  return MsgpackSerializer::Serialize(data);
}

SecretKeyBatch BulkSerializer::DeserializeSecretKeys(
    yacl::ByteContainerView in,
    std::shared_ptr<BfvParameters> expected_params) {
  auto data = ParseBundle(in, BundleObjectType::kSecretKey);
  auto params = ResolveParametersForDeserialize(
      data, std::move(expected_params), BundleObjectType::kSecretKey);
  return DeserializeEntries<SecretKeyBatch>(
      data, std::move(params),
      [](yacl::ByteContainerView payload,
         const std::shared_ptr<BfvParameters> &params) {
        return SecretKey::from_bytes(payload, params);
      });
}

yacl::Buffer BulkSerializer::SerializePublicKeys(
    const std::vector<PublicKey> &public_keys,
    std::shared_ptr<BfvParameters> params) {
  auto resolved_params = ResolveParametersForSerialize(
      public_keys, std::move(params), BundleObjectType::kPublicKey);
  auto data = BuildBundle(BundleObjectType::kPublicKey, resolved_params);
  data.payloads = SerializeEntries(public_keys);
  return MsgpackSerializer::Serialize(data);
}

PublicKeyBatch BulkSerializer::DeserializePublicKeys(
    yacl::ByteContainerView in,
    std::shared_ptr<BfvParameters> expected_params) {
  auto data = ParseBundle(in, BundleObjectType::kPublicKey);
  auto params = ResolveParametersForDeserialize(
      data, std::move(expected_params), BundleObjectType::kPublicKey);
  return DeserializeEntries<PublicKeyBatch>(
      data, std::move(params),
      [](yacl::ByteContainerView payload,
         const std::shared_ptr<BfvParameters> &params) {
        return PublicKey::from_bytes(payload, params);
      });
}

yacl::Buffer BulkSerializer::SerializeGaloisKeys(
    const std::vector<GaloisKey> &galois_keys,
    std::shared_ptr<BfvParameters> params) {
  auto resolved_params = ResolveParametersForSerialize(
      galois_keys, std::move(params), BundleObjectType::kGaloisKey);
  auto data = BuildBundle(BundleObjectType::kGaloisKey, resolved_params);
  data.payloads = SerializeEntries(galois_keys);
  return MsgpackSerializer::Serialize(data);
}

GaloisKeyBatch BulkSerializer::DeserializeGaloisKeys(
    yacl::ByteContainerView in,
    std::shared_ptr<BfvParameters> expected_params) {
  auto data = ParseBundle(in, BundleObjectType::kGaloisKey);
  auto params = ResolveParametersForDeserialize(
      data, std::move(expected_params), BundleObjectType::kGaloisKey);
  return DeserializeEntries<GaloisKeyBatch>(
      data, std::move(params),
      [](yacl::ByteContainerView payload,
         const std::shared_ptr<BfvParameters> &params) {
        return GaloisKey::from_bytes(payload, params);
      });
}

yacl::Buffer BulkSerializer::SerializeKeySwitchingKeys(
    const std::vector<KeySwitchingKey> &key_switching_keys,
    std::shared_ptr<BfvParameters> params) {
  auto resolved_params =
      ResolveParametersForSerialize(key_switching_keys, std::move(params),
                                    BundleObjectType::kKeySwitchingKey);
  auto data = BuildBundle(BundleObjectType::kKeySwitchingKey, resolved_params);
  data.payloads = SerializeEntries(key_switching_keys);
  return MsgpackSerializer::Serialize(data);
}

KeySwitchingKeyBatch BulkSerializer::DeserializeKeySwitchingKeys(
    yacl::ByteContainerView in,
    std::shared_ptr<BfvParameters> expected_params) {
  auto data = ParseBundle(in, BundleObjectType::kKeySwitchingKey);
  auto params = ResolveParametersForDeserialize(
      data, std::move(expected_params), BundleObjectType::kKeySwitchingKey);
  return DeserializeEntries<KeySwitchingKeyBatch>(
      data, std::move(params),
      [](yacl::ByteContainerView payload,
         const std::shared_ptr<BfvParameters> &params) {
        return KeySwitchingKey::from_bytes(payload, params);
      });
}

}  // namespace bfv
}  // namespace crypto
