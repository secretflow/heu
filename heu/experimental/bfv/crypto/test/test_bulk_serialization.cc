#include <gtest/gtest.h>

#include <random>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/bulk_serialization.h"
#include "crypto/encoding.h"
#include "crypto/evaluation_key.h"
#include "crypto/galois_key.h"
#include "crypto/key_switching_key.h"
#include "crypto/multiplicator.h"
#include "crypto/plaintext.h"
#include "crypto/public_key.h"
#include "crypto/relinearization_key.h"
#include "crypto/secret_key.h"
#include "crypto/serialization/serialization_exceptions.h"
#include "math/context.h"
#include "math/poly.h"
#include "math/representation.h"

using namespace crypto::bfv;
namespace ser = crypto::bfv::serialization;

class BulkSerializationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    rng_.seed(42);
    try {
      params_ = BfvParameters::default_arc(2, 16);
      mismatched_params_ = BfvParameters::default_arc(3, 32);
    } catch (const std::exception &) {
      params_ = nullptr;
      mismatched_params_ = nullptr;
    }
  }

  std::vector<uint64_t> values(uint64_t base) const {
    return {base + 1, base + 2, base + 3, base + 4};
  }

  Ciphertext make_ciphertext(uint64_t base) {
    auto ctx = params_->ctx_at_level(0);
    auto c0 = ::bfv::math::rq::Poly::random(
        ctx, ::bfv::math::rq::Representation::Ntt, rng_);
    auto c1 = ::bfv::math::rq::Poly::random(
        ctx, ::bfv::math::rq::Representation::Ntt, rng_);
    auto ct = Ciphertext::from_polynomials({c0, c1}, params_);
    if (base % 2 == 0) {
      return ct;
    }
    return Ciphertext::zero(params_);
  }

  ::bfv::math::rq::Poly make_small_poly() {
    auto ctx = params_->ctx_at_level(0);
    return ::bfv::math::rq::Poly::small(
        ctx, ::bfv::math::rq::Representation::PowerBasis, 10, rng_);
  }

  std::mt19937_64 rng_;
  std::shared_ptr<BfvParameters> params_;
  std::shared_ptr<BfvParameters> mismatched_params_;
};

TEST_F(BulkSerializationTest, PlaintextBatchRoundTrip) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto encoding = Encoding::poly();
  std::vector<Plaintext> plaintexts = {
      Plaintext::encode(values(0), encoding, params_),
      Plaintext::encode(values(10), encoding, params_),
  };

  auto bundle = BulkSerializer::SerializePlaintexts(plaintexts);
  auto restored = BulkSerializer::DeserializePlaintexts(bundle);

  ASSERT_NE(restored.params, nullptr);
  EXPECT_EQ(*restored.params, *params_);
  ASSERT_EQ(restored.items.size(), plaintexts.size());
  EXPECT_EQ(restored.items[0], plaintexts[0]);
  EXPECT_EQ(restored.items[1], plaintexts[1]);
}

TEST_F(BulkSerializationTest, EmptyPlaintextBatchRoundTrip) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  std::vector<Plaintext> plaintexts;
  auto bundle = BulkSerializer::SerializePlaintexts(plaintexts, params_);
  auto restored = BulkSerializer::DeserializePlaintexts(bundle, params_);

  EXPECT_EQ(restored.params, params_);
  EXPECT_TRUE(restored.items.empty());
}

TEST_F(BulkSerializationTest, CiphertextBatchRoundTripWithArena) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  std::vector<Ciphertext> ciphertexts = {
      Ciphertext::zero(params_),
      make_ciphertext(2),
  };

  auto bundle = BulkSerializer::SerializeCiphertexts(ciphertexts);
  auto restored = BulkSerializer::DeserializeCiphertexts(
      bundle, params_, ::bfv::util::ArenaHandle::Shared());

  EXPECT_EQ(restored.params, params_);
  ASSERT_EQ(restored.items.size(), ciphertexts.size());
  EXPECT_EQ(restored.items[0], ciphertexts[0]);
  EXPECT_EQ(restored.items[1], ciphertexts[1]);
}

TEST_F(BulkSerializationTest, ParameterMismatchRejected) {
  if (!params_ || !mismatched_params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto encoding = Encoding::poly();
  std::vector<Plaintext> plaintexts = {
      Plaintext::encode(values(0), encoding, params_),
  };

  auto bundle = BulkSerializer::SerializePlaintexts(plaintexts);
  EXPECT_THROW(
      BulkSerializer::DeserializePlaintexts(bundle, mismatched_params_),
      ser::ParameterMismatchException);
}

TEST_F(BulkSerializationTest, EvaluationKeyBatchRoundTrip) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto sk = SecretKey::random(params_, rng_);
  auto inner_sum_key =
      EvaluationKeyBuilder::create(sk).enable_inner_sum().build(rng_);
  auto rotation_key = EvaluationKeyBuilder::create(sk)
                          .enable_row_rotation()
                          .enable_column_rotation(1)
                          .build(rng_);

  std::vector<EvaluationKey> keys = {inner_sum_key, rotation_key};
  auto bundle = BulkSerializer::SerializeEvaluationKeys(keys);
  auto restored = BulkSerializer::DeserializeEvaluationKeys(bundle, params_);

  EXPECT_EQ(restored.params, params_);
  ASSERT_EQ(restored.items.size(), keys.size());
  EXPECT_EQ(restored.items[0], inner_sum_key);
  EXPECT_EQ(restored.items[1], rotation_key);
  EXPECT_TRUE(restored.items[0].supports_inner_sum());
  EXPECT_TRUE(restored.items[1].supports_row_rotation());
  EXPECT_TRUE(restored.items[1].supports_column_rotation_by(1));

  auto values_vec = values(0);
  auto pt = Plaintext::encode(values_vec, Encoding::simd(), params_);
  auto ct = sk.encrypt(pt, rng_);
  auto summed = restored.items[0].computes_inner_sum(ct);
  auto decoded =
      sk.decrypt(summed, Encoding::simd()).decode_uint64(Encoding::simd());

  uint64_t expected_sum = 0;
  for (auto value : values_vec) {
    expected_sum = (expected_sum + value) % params_->plaintext_modulus();
  }
  for (size_t i = 0; i < values_vec.size(); ++i) {
    EXPECT_EQ(decoded[i], expected_sum);
  }
}

TEST_F(BulkSerializationTest, RelinearizationKeyBatchRoundTrip) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto sk = SecretKey::random(params_, rng_);
  auto key_a = RelinearizationKey::from_secret_key(sk, rng_);
  auto key_b = RelinearizationKey::from_secret_key(sk, rng_);

  std::vector<RelinearizationKey> keys = {key_a, key_b};
  auto bundle = BulkSerializer::SerializeRelinearizationKeys(keys);
  auto restored =
      BulkSerializer::DeserializeRelinearizationKeys(bundle, params_);

  EXPECT_EQ(restored.params, params_);
  ASSERT_EQ(restored.items.size(), keys.size());
  EXPECT_EQ(restored.items[0], key_a);
  EXPECT_EQ(restored.items[1], key_b);

  auto pt = Plaintext::encode(values(3), Encoding::simd(), params_);
  auto ct = sk.encrypt(pt, rng_);
  auto multiplicator = Multiplicator::create_default(restored.items[0]);
  auto product = multiplicator->multiply(ct, ct);
  auto decoded =
      sk.decrypt(product, Encoding::simd()).decode_uint64(Encoding::simd());

  auto input = pt.decode_uint64(Encoding::simd());
  for (size_t i = 0; i < values(3).size(); ++i) {
    EXPECT_EQ(decoded[i], (input[i] * input[i]) % params_->plaintext_modulus());
  }
}

TEST_F(BulkSerializationTest, ParameterMismatchRejectedForEvaluationKeyBatch) {
  if (!params_ || !mismatched_params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto sk = SecretKey::random(params_, rng_);
  auto eval_key =
      EvaluationKeyBuilder::create(sk).enable_inner_sum().build(rng_);

  auto bundle = BulkSerializer::SerializeEvaluationKeys({eval_key});
  EXPECT_THROW(
      BulkSerializer::DeserializeEvaluationKeys(bundle, mismatched_params_),
      ser::ParameterMismatchException);
}

TEST_F(BulkSerializationTest, SecretKeyBatchRoundTrip) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto sk_a = SecretKey::random(params_, rng_);
  auto sk_b = SecretKey::random(params_, rng_);
  std::vector<SecretKey> secret_keys;
  secret_keys.emplace_back(
      SecretKey::from_coefficients(sk_a.coefficients(), params_));
  secret_keys.emplace_back(
      SecretKey::from_coefficients(sk_b.coefficients(), params_));

  auto bundle = BulkSerializer::SerializeSecretKeys(secret_keys);
  auto restored = BulkSerializer::DeserializeSecretKeys(bundle, params_);

  EXPECT_EQ(restored.params, params_);
  ASSERT_EQ(restored.items.size(), 2u);
  EXPECT_EQ(restored.items[0].coefficients(), sk_a.coefficients());
  EXPECT_EQ(restored.items[1].coefficients(), sk_b.coefficients());

  auto pt = Plaintext::encode(values(0), Encoding::poly(), params_);
  auto ct = restored.items[0].encrypt(pt, rng_);
  auto decoded = restored.items[0].decrypt(ct).decode_uint64(Encoding::poly());
  auto expected = pt.decode_uint64(Encoding::poly());
  for (size_t i = 0; i < values(0).size(); ++i) {
    EXPECT_EQ(decoded[i], expected[i]);
  }
}

TEST_F(BulkSerializationTest, PublicKeyBatchRoundTrip) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto sk = SecretKey::random(params_, rng_);
  auto pk_a = PublicKey::from_secret_key(sk, rng_);
  auto pk_b = PublicKey::from_secret_key(sk, rng_);

  auto bundle = BulkSerializer::SerializePublicKeys({pk_a, pk_b});
  auto restored = BulkSerializer::DeserializePublicKeys(bundle, params_);

  EXPECT_EQ(restored.params, params_);
  ASSERT_EQ(restored.items.size(), 2u);
  EXPECT_EQ(restored.items[0], pk_a);
  EXPECT_EQ(restored.items[1], pk_b);

  auto pt = Plaintext::encode(values(5), Encoding::poly(), params_);
  auto ct = restored.items[0].encrypt(pt, rng_);
  auto decoded = sk.decrypt(ct).decode_uint64(Encoding::poly());
  auto expected = pt.decode_uint64(Encoding::poly());
  for (size_t i = 0; i < values(5).size(); ++i) {
    EXPECT_EQ(decoded[i], expected[i]);
  }
}

TEST_F(BulkSerializationTest, GaloisKeyBatchRoundTrip) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto sk = SecretKey::random(params_, rng_);
  auto gk_a = GaloisKey::create(sk, 9, 0, 0, rng_);
  auto gk_b = GaloisKey::create(sk, 11, 0, 0, rng_);

  auto bundle = BulkSerializer::SerializeGaloisKeys({gk_a, gk_b});
  auto restored = BulkSerializer::DeserializeGaloisKeys(bundle, params_);

  EXPECT_EQ(restored.params, params_);
  ASSERT_EQ(restored.items.size(), 2u);
  EXPECT_EQ(restored.items[0], gk_a);
  EXPECT_EQ(restored.items[1], gk_b);

  auto pt = Plaintext::encode(values(2), Encoding::simd(), params_);
  auto ct = sk.encrypt(pt, rng_);
  auto original_pt = sk.decrypt(gk_a.apply(ct), Encoding::simd());
  auto restored_pt = sk.decrypt(restored.items[0].apply(ct), Encoding::simd());
  EXPECT_EQ(original_pt.decode_uint64(Encoding::simd()),
            restored_pt.decode_uint64(Encoding::simd()));
}

TEST_F(BulkSerializationTest, KeySwitchingKeyBatchRoundTrip) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto sk = SecretKey::random(params_, rng_);
  auto ksk_a = KeySwitchingKey::create(sk, make_small_poly(), 0, 0, rng_);
  auto ksk_b = KeySwitchingKey::create(sk, make_small_poly(), 0, 0, rng_);

  auto bundle = BulkSerializer::SerializeKeySwitchingKeys({ksk_a, ksk_b});
  auto restored = BulkSerializer::DeserializeKeySwitchingKeys(bundle, params_);

  EXPECT_EQ(restored.params, params_);
  ASSERT_EQ(restored.items.size(), 2u);
  EXPECT_EQ(restored.items[0], ksk_a);
  EXPECT_EQ(restored.items[1], ksk_b);
}

TEST_F(BulkSerializationTest, ParameterMismatchRejectedForSecretKeyBatch) {
  if (!params_ || !mismatched_params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto sk = SecretKey::random(params_, rng_);
  std::vector<SecretKey> secret_keys;
  secret_keys.emplace_back(
      SecretKey::from_coefficients(sk.coefficients(), params_));
  auto bundle = BulkSerializer::SerializeSecretKeys(secret_keys);
  EXPECT_THROW(
      BulkSerializer::DeserializeSecretKeys(bundle, mismatched_params_),
      ser::ParameterMismatchException);
}

TEST_F(BulkSerializationTest, TypeMismatchRejected) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto encoding = Encoding::poly();
  std::vector<Plaintext> plaintexts = {
      Plaintext::encode(values(0), encoding, params_),
  };

  auto bundle = BulkSerializer::SerializePlaintexts(plaintexts);
  EXPECT_THROW(BulkSerializer::DeserializeCiphertexts(bundle, params_),
               ser::SchemaValidationException);
}

TEST_F(BulkSerializationTest, KeyTypeMismatchRejected) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto sk = SecretKey::random(params_, rng_);
  auto relin_key = RelinearizationKey::from_secret_key(sk, rng_);
  auto bundle = BulkSerializer::SerializeRelinearizationKeys({relin_key});

  EXPECT_THROW(BulkSerializer::DeserializeEvaluationKeys(bundle, params_),
               ser::SchemaValidationException);
}

TEST_F(BulkSerializationTest, PublicKeyTypeMismatchRejected) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto sk = SecretKey::random(params_, rng_);
  auto pk = PublicKey::from_secret_key(sk, rng_);
  auto bundle = BulkSerializer::SerializePublicKeys({pk});

  EXPECT_THROW(BulkSerializer::DeserializeSecretKeys(bundle, params_),
               ser::SchemaValidationException);
}

TEST_F(BulkSerializationTest, CorruptedBundleRejected) {
  if (!params_) {
    GTEST_SKIP() << "Parameters not available";
  }

  auto encoding = Encoding::poly();
  std::vector<Plaintext> plaintexts = {
      Plaintext::encode(values(0), encoding, params_),
  };

  auto bundle = BulkSerializer::SerializePlaintexts(plaintexts);
  ASSERT_GT(bundle.size(), 8);
  bundle.data<uint8_t>()[bundle.size() - 1] ^= 0x01;

  EXPECT_THROW(BulkSerializer::DeserializePlaintexts(bundle),
               ser::SerializationException);
}
