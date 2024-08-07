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

#include "heu/algorithms/incubator/mock_fhe/base.h"
#include "heu/spi/he/sketches/common/batch_encoder.h"
#include "heu/spi/he/sketches/common/plain_encoder.h"

namespace heu::algos::mock_fhe {

class PlainEncoder : public spi::PlainEncoderSketch<Plaintext> {
 public:
  explicit PlainEncoder(size_t poly_degree) : poly_degree_(poly_degree) {}

  std::string ToString() const override;

  Plaintext FromStringT(std::string_view) const override;

  Plaintext EncodeT(int64_t message) const override;
  Plaintext EncodeT(uint64_t message) const override;
  Plaintext EncodeT(double) const override;
  Plaintext EncodeT(const std::complex<double> &) const override;

  void DecodeT(const Plaintext &pt, int64_t *out) const override;
  void DecodeT(const Plaintext &pt, uint64_t *out) const override;
  void DecodeT(const Plaintext &, double *) const override;
  void DecodeT(const Plaintext &, std::complex<double> *) const override;

 private:
  size_t poly_degree_;
};

class BatchEncoder : public spi::BatchEncoderSketch<Plaintext> {
 public:
  explicit BatchEncoder(size_t poly_degree) : poly_degree_(poly_degree) {}

  size_t SlotCount() const override;

  std::string ToString() const override;

  Plaintext FromStringT(std::string_view) const override;

  Plaintext EncodeT(absl::Span<const int64_t> message) const override;
  Plaintext EncodeT(absl::Span<const uint64_t> message) const override;
  Plaintext EncodeT(absl::Span<const double>) const override;
  Plaintext EncodeT(absl::Span<const std::complex<double>>) const override;
  Plaintext EncodeT(int64_t message) const override;
  Plaintext EncodeT(uint64_t message) const override;
  Plaintext EncodeT(double message) const override;
  Plaintext EncodeT(const std::complex<double> &message) const override;

  void DecodeT(const Plaintext &pt, absl::Span<int64_t> out) const override;
  void DecodeT(const Plaintext &pt, absl::Span<uint64_t> out) const override;
  void DecodeT(const Plaintext &, absl::Span<double>) const override;
  void DecodeT(const Plaintext &,
               absl::Span<std::complex<double>>) const override;

 private:
  size_t poly_degree_;
};

// CkksEncoder for mock_fhe
class CkksEncoder : public spi::BatchEncoderSketch<Plaintext> {
 public:
  explicit CkksEncoder(size_t poly_degree, int64_t scale);

  size_t SlotCount() const override;

  std::string ToString() const override;

  Plaintext FromStringT(std::string_view) const override;

  Plaintext EncodeT(absl::Span<const int64_t> message) const override;
  Plaintext EncodeT(absl::Span<const uint64_t> message) const override;
  Plaintext EncodeT(absl::Span<const double> message) const override;
  Plaintext EncodeT(
      absl::Span<const std::complex<double>> message) const override;

  // The number repeats for N/2 times to fill all slots.
  Plaintext EncodeT(int64_t message) const override;
  Plaintext EncodeT(uint64_t message) const override;
  Plaintext EncodeT(double message) const override;
  // Encodes a double-precision complex number into a plaintext polynomial.
  // Append zeros to fill all slots. (keep same with SEAL)
  Plaintext EncodeT(const std::complex<double> &message) const override;

  void DecodeT(const Plaintext &pt, absl::Span<int64_t> out) const override;
  void DecodeT(const Plaintext &pt, absl::Span<uint64_t> out) const override;
  void DecodeT(const Plaintext &pt, absl::Span<double> out) const override;
  void DecodeT(const Plaintext &pt,
               absl::Span<std::complex<double>> out) const override;

 private:
  size_t half_degree_;
  int64_t scale_;
};

}  // namespace heu::algos::mock_fhe
