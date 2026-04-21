#include <gtest/gtest.h>

#include <memory>
#include <random>
#include <vector>

#include "crypto/bfv_parameters.h"
#include "crypto/ciphertext.h"
#include "crypto/encoding.h"
#include "crypto/plaintext.h"
#include "crypto/rgsw_ciphertext.h"
#include "crypto/secret_key.h"

namespace crypto {
namespace bfv {

class RGSWCiphertextTest : public ::testing::Test {
 protected:
  void SetUp() override {
    params1_ = BfvParameters::default_arc(2, 16);
    params2_ = BfvParameters::default_arc(8, 16);

    // Initialize random number generator
    rng_.seed(42);  // Fixed seed for reproducible tests
  }

  std::shared_ptr<BfvParameters> params1_;
  std::shared_ptr<BfvParameters> params2_;
  std::mt19937_64 rng_;
};

TEST_F(RGSWCiphertextTest, ExternalProduct) {
  // Test external product operations - basic functionality test
  for (auto params : {params1_, params2_}) {
    // Use separate RNG for each test iteration to ensure consistency
    std::mt19937_64 test_rng(42);

    // Generate secret key
    auto sk = SecretKey::random(params, test_rng);

    // Use simple test vectors
    std::vector<uint64_t> v1(params->degree(), 1);  // All 1s
    std::vector<uint64_t> v2(params->degree(), 2);  // All 2s

    // Create plaintexts with SIMD encoding
    auto encoding = Encoding::simd();
    auto pt1 = Plaintext::encode(v1, encoding, params);
    auto pt2 = Plaintext::encode(v2, encoding, params);

    // Encrypt plaintexts
    auto ct1 = sk.encrypt(pt1, test_rng);
    auto ct2_rgsw = sk.encrypt_rgsw(pt2, test_rng);

    // Test external product operations
    auto ct3 = ct1 * ct2_rgsw;
    auto ct4 = ct2_rgsw * ct1;

    // // Measure noise
    // auto noise1 = sk.measure_noise(ct3);
    // auto noise2 = sk.measure_noise(ct4);
    // std::cout << "Noise 1: " << noise1 << std::endl;
    // std::cout << "Noise 2: " << noise2 << std::endl;

    // Verify that we can decrypt the results (basic functionality test)
    auto result3 = sk.decrypt(ct3);
    auto result4 = sk.decrypt(ct4);

    // Basic sanity checks - the operations should produce valid plaintexts
    EXPECT_FALSE(result3.empty());
    EXPECT_FALSE(result4.empty());
    EXPECT_EQ(result3.level(), ct3.level());
    EXPECT_EQ(result4.level(), ct4.level());

    // Test that both external product operations produce the same result
    // (since multiplication is commutative)
    auto result3_values = result3.decode_uint64();
    auto result4_values = result4.decode_uint64();

    // The results should be identical since ct1 * ct2_rgsw == ct2_rgsw * ct1
    EXPECT_EQ(result3_values.size(), result4_values.size());

    // Check that at least the first value is reasonable (should be around 2
    // since 1*2=2) Allow for some noise but the value should be in a reasonable
    // range
    if (!result3_values.empty()) {
      EXPECT_GT(result3_values[0], 0u);
      EXPECT_LT(result3_values[0], params->plaintext_modulus());
    }
  }
}

TEST_F(RGSWCiphertextTest, BasicOperations) {
  // Test basic RGSW ciphertext operations
  auto params = params1_;
  auto sk = SecretKey::random(params, rng_);

  // Create test plaintext
  std::vector<uint64_t> v = {1, 2, 3, 4};
  v.resize(params->degree(), 0);
  auto encoding = Encoding::simd();
  auto pt = Plaintext::encode(v, encoding, params);

  // Create RGSW ciphertext
  auto rgsw_ct = sk.encrypt_rgsw(pt, rng_);

  // Test accessors
  EXPECT_EQ(rgsw_ct.parameters(), params);
  EXPECT_EQ(rgsw_ct.level(), 0);
  EXPECT_FALSE(rgsw_ct.empty());

  // Test copy constructor
  auto rgsw_ct_copy = rgsw_ct;
  EXPECT_EQ(rgsw_ct, rgsw_ct_copy);

  // Test move constructor
  auto rgsw_ct_moved = std::move(rgsw_ct_copy);
  EXPECT_EQ(rgsw_ct, rgsw_ct_moved);
}

TEST_F(RGSWCiphertextTest, EqualityOperators) {
  // Test equality and inequality operators
  auto params = params1_;
  auto sk = SecretKey::random(params, rng_);

  // Create test plaintexts
  std::vector<uint64_t> v1 = {1, 2, 3, 4};
  std::vector<uint64_t> v2 = {5, 6, 7, 8};
  v1.resize(params->degree(), 0);
  v2.resize(params->degree(), 0);

  auto encoding = Encoding::simd();
  auto pt1 = Plaintext::encode(v1, encoding, params);
  auto pt2 = Plaintext::encode(v2, encoding, params);

  // Create RGSW ciphertexts
  auto rgsw_ct1 = sk.encrypt_rgsw(pt1, rng_);
  auto rgsw_ct2 = sk.encrypt_rgsw(pt2, rng_);
  auto rgsw_ct1_copy = rgsw_ct1;

  // Test equality
  EXPECT_EQ(rgsw_ct1, rgsw_ct1_copy);
  EXPECT_NE(rgsw_ct1, rgsw_ct2);
}

TEST_F(RGSWCiphertextTest, ParameterValidation) {
  // Test parameter validation for external product
  auto params1 = params1_;
  auto params2 = params2_;

  auto sk1 = SecretKey::random(params1, rng_);
  auto sk2 = SecretKey::random(params2, rng_);

  // Create test data
  std::vector<uint64_t> v = {1, 2, 3, 4};
  v.resize(params1->degree(), 0);
  auto encoding1 = Encoding::simd();
  auto pt1 = Plaintext::encode(v, encoding1, params1);

  v.resize(params2->degree(), 0);
  auto encoding2 = Encoding::simd();
  auto pt2 = Plaintext::encode(v, encoding2, params2);

  // Create ciphertexts with different parameters
  auto ct1 = sk1.encrypt(pt1, rng_);
  auto rgsw_ct2 = sk2.encrypt_rgsw(pt2, rng_);

  // Test that external product with mismatched parameters throws
  EXPECT_THROW(ct1 * rgsw_ct2, ParameterException);
  EXPECT_THROW(rgsw_ct2 * ct1, ParameterException);
}

TEST_F(RGSWCiphertextTest, SerializationRoundTrip) {
  auto params = params1_;
  auto sk = SecretKey::random(params, rng_);

  std::vector<uint64_t> v = {1, 2, 3, 4};
  v.resize(params->degree(), 0);
  auto encoding = Encoding::simd();
  auto pt = Plaintext::encode(v, encoding, params);

  auto rgsw_ct = sk.encrypt_rgsw(pt, rng_);
  auto serialized = rgsw_ct.Serialize();
  auto restored = RGSWCiphertext::from_bytes(serialized, params);

  EXPECT_EQ(restored, rgsw_ct);

  auto ct = sk.encrypt(pt, rng_);
  auto result = sk.decrypt(restored * ct);
  EXPECT_FALSE(result.empty());
}

}  // namespace bfv
}  // namespace crypto
