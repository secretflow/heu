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

#include "yacl/math/mpint/mp_int.h"

#include "heu/spi/he/base.h"

namespace heu::lib::spi {

using MPInt = yacl::math::MPInt;

// Encode single message
class TrivialEncoder {
 public:
  // Print encoder info, include encoding params
  virtual std::string ToString() const = 0;

  virtual Item Encode(int64_t message) const = 0;
  virtual Item Encode(uint64_t message) const = 0;
  virtual Item Encode(double message) const = 0;
  virtual Item Encode(const MPInt& message) const = 0;

  virtual int64_t DecodeInt64(const Item& plaintext) const = 0;
  virtual uint64_t DecodeUint64(const Item& plaintext) const = 0;
  virtual double DecodeDouble(const Item& plaintext) const = 0;
  virtual MPInt DecodeMpint(const Item& plaintext) const = 0;
};

// Encode a batch of messages
class BatchEncoder {
 public:
  // Print encoder info, include encoding params
  virtual std::string ToString() const = 0;

  virtual Item Encode(std::vector<int64_t>& message) const = 0;
  virtual Item Encode(std::vector<uint64_t>& message) const = 0;
  virtual Item Encode(std::vector<double>& message) const = 0;
  virtual Item Encode(std::vector<std::complex<double>>& message) const = 0;

  virtual void Decode(const Item& plaintext,
                      std::vector<int64_t>* message) const = 0;
  virtual void Decode(const Item& plaintext,
                      std::vector<uint64_t>* message) const = 0;
  virtual void Decode(const Item& plaintext,
                      std::vector<double>* message) const = 0;
  virtual void Decode(const Item& plaintext,
                      std::vector<std::complex<double>>* message) const = 0;

  virtual std::vector<int64_t> DecodeInt64(const Item& plaintext) const = 0;
  virtual std::vector<uint64_t> DecodeUint64(const Item& plaintext) const = 0;
  virtual std::vector<double> DecodeDouble(const Item& plaintext) const = 0;
  virtual std::vector<std::complex<double>> DecodeComplex(
      const Item& plaintext) const = 0;

  virtual int64_t SlotCount() const = 0;
};

}  // namespace heu::lib::spi
