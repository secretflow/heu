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

#include <complex>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "absl/types/span.h"
#include "yacl/math/mpint/mp_int.h"

#include "heu/spi/he/item.h"

namespace heu::lib::spi {

using MPInt = yacl::math::MPInt;

// Encode cleartext into plaintext
// Cleartext --(encoder)--> Plaintext --(Encryptor)--> Ciphertext
class Encoder {
 public:
  virtual ~Encoder() = default;

  // Print encoder info, include encoding params
  virtual std::string ToString() const = 0;

  // directly parse plaintext from string, skip encode
  virtual Item FromString(std::string_view plaintext) const = 0;

  // The maximum number of cleartexts that can be encoded in a single plaintext
  // BatchEncoder: SlotCount() > 1
  // PlainEncoder: SlotCount() == 1
  virtual size_t SlotCount() const = 0;

  // if size(message) <= SlotCount(), encode the entire message into a single
  // plaintext.
  // Otherwise, encode it into ⌈size(message)/SlotCount()⌉ separate plaintexts.
  virtual Item Encode(absl::Span<const int64_t> message) const = 0;
  virtual Item Encode(absl::Span<const uint64_t> message) const = 0;
  virtual Item Encode(absl::Span<const double> message) const = 0;
  virtual Item Encode(absl::Span<const std::complex<double>> message) const = 0;

  // Get the number of cleartexts contained within the Plaintext(s), where the
  // result is always an integer multiple of SlotCount().
  //
  // Please note that automatically padded cleartexts are also counted. For
  // example, if SlotCount() equals 4096, then
  // GetCleartextCount(Encode(...4097 Cleartexts...)) would return 8192.
  virtual int64_t GetCleartextCount(const Item& plaintexts) const = 0;

  virtual void Decode(const Item& plaintexts,
                      absl::Span<int64_t> out_message) const = 0;
  virtual void Decode(const Item& plaintexts,
                      absl::Span<uint64_t> out_message) const = 0;
  virtual void Decode(const Item& plaintexts,
                      absl::Span<double> out_message) const = 0;
  virtual void Decode(const Item& plaintexts,
                      absl::Span<std::complex<double>> out_message) const = 0;

  virtual std::vector<int64_t> DecodeInt64(const Item& plaintexts) const = 0;
  virtual std::vector<uint64_t> DecodeUint64(const Item& plaintexts) const = 0;
  virtual std::vector<double> DecodeDouble(const Item& plaintexts) const = 0;
  virtual std::vector<std::complex<double>> DecodeComplex(
      const Item& plaintexts) const = 0;

  // ==================================================================== //
  // <<<  The following functions are only supported by PlainEncoder  >>> //
  // <<<       If you are using BatchEncoder, do not call them        >>> //
  // ==================================================================== //

  virtual Item EncodeScalar(int64_t message) const = 0;
  virtual Item EncodeScalar(uint64_t message) const = 0;
  virtual Item EncodeScalar(double message) const = 0;
  virtual Item EncodeScalar(const std::complex<double>& message) const = 0;

  // Decode single cleartext.
  // Must have GetCleartextCount(plaintext) == 1.
  virtual int64_t DecodeScalarInt64(const Item& plaintext) const = 0;
  virtual uint64_t DecodeScalarUint64(const Item& plaintext) const = 0;
  virtual double DecodeScalarDouble(const Item& plaintext) const = 0;
  virtual std::complex<double> DecodeScalarComplex(
      const Item& plaintext) const = 0;
};

}  // namespace heu::lib::spi
