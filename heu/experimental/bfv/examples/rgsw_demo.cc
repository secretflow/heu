#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "heu/experimental/bfv/crypto/bfv_parameters.h"
#include "heu/experimental/bfv/crypto/encoding.h"
#include "heu/experimental/bfv/crypto/plaintext.h"
#include "heu/experimental/bfv/crypto/rgsw_ciphertext.h"
#include "heu/experimental/bfv/crypto/secret_key.h"

using namespace crypto::bfv;

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
  std::cout << "=== BFV RGSW Demo ===\n" << std::endl;

  auto params = BfvParameters::default_arc(2, 16);
  std::mt19937_64 rng(42);
  auto secret_key = SecretKey::random(params, rng);

  std::vector<uint64_t> data_values(params->degree(), 0);
  std::vector<uint64_t> mask_values(params->degree(), 0);
  for (size_t i = 0; i < std::min<size_t>(8, data_values.size()); ++i) {
    data_values[i] = static_cast<uint64_t>(i + 1);
    mask_values[i] = 2;
  }

  auto data_plaintext =
      Plaintext::encode(data_values, Encoding::simd(), params);
  auto mask_plaintext =
      Plaintext::encode(mask_values, Encoding::simd(), params);
  auto data_ciphertext = secret_key.encrypt(data_plaintext, rng);
  auto rgsw_ciphertext = secret_key.encrypt_rgsw(mask_plaintext, rng);

  auto serialized = rgsw_ciphertext.Serialize();
  auto restored = RGSWCiphertext::from_bytes(serialized, params);
  Require(restored == rgsw_ciphertext,
          "RGSW serialization round-trip did not preserve the ciphertext");

  auto result_left = data_ciphertext * restored;
  auto result_right = restored * data_ciphertext;
  auto decoded_left = secret_key.decrypt(result_left, Encoding::simd())
                          .decode_uint64(Encoding::simd());
  auto decoded_right = secret_key.decrypt(result_right, Encoding::simd())
                           .decode_uint64(Encoding::simd());

  Require(decoded_left == decoded_right,
          "left and right external products should decrypt to the same value");
  Require(!decoded_left.empty(), "external product should decrypt to data");
  for (uint64_t value : decoded_left) {
    Require(
        value < params->plaintext_modulus(),
        "decrypted RGSW external-product slot exceeded the plaintext modulus");
  }

  PrintVectorPrefix("External product result", decoded_left);
  PrintVectorPrefix("Commuted external product result", decoded_right);

  return 0;
}
