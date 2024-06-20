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

#include "heu/algorithms/mock_fhe/encoders.h"

namespace heu::algos::mock_fhe {

std::string PlainEncoder::ToString() const {
  return "PlainEncoder from mock_fhe lib";
}

Plaintext PlainEncoder::FromStringT(std::string_view) const {
  YACL_THROW("mock_fhe: directly parse from string not implemented");
}

Plaintext PlainEncoder::EncodeT(int64_t message) const {
  std::vector<int64_t> vec(poly_degree_);
  vec[0] = message;
  return Plaintext(std::move(vec));
}

Plaintext PlainEncoder::EncodeT(uint64_t message) const {
  std::vector<int64_t> vec(poly_degree_);
  vec[0] = static_cast<int64_t>(message);
  return Plaintext(std::move(vec));
}

Plaintext PlainEncoder::EncodeT(double) const {
  YACL_THROW("PlainEncoder cannot encode float number");
}

Plaintext PlainEncoder::EncodeT(const std::complex<double> &) const {
  YACL_THROW("PlainEncoder cannot encode complex number");
}

void PlainEncoder::DecodeT(const Plaintext &pt, int64_t *out) const {
  YACL_ENFORCE(pt->size() > 0,
               "pt is an un-initialized plaintext, cannot decode");
  *out = pt.array_[0];
}

void PlainEncoder::DecodeT(const Plaintext &pt, uint64_t *out) const {
  YACL_ENFORCE(pt->size() > 0,
               "pt is an un-initialized plaintext, cannot decode");
  *out = pt.array_[0];
}

void PlainEncoder::DecodeT(const Plaintext &, double *) const {
  YACL_THROW("PlainEncoder does not support float number");
}

void PlainEncoder::DecodeT(const Plaintext &, std::complex<double> *) const {
  YACL_THROW("PlainEncoder does not support complex number");
}

size_t BatchEncoder::SlotCount() const { return poly_degree_; }

std::string BatchEncoder::ToString() const {
  return fmt::format("BatchEncoder from mock_fhe lib, slot={}", poly_degree_);
}

Plaintext BatchEncoder::FromStringT(std::string_view) const {
  YACL_THROW("mock_fhe: directly parse from string not implemented");
}

Plaintext BatchEncoder::EncodeT(absl::Span<const int64_t> message) const {
  YACL_ENFORCE(message.size() <= poly_degree_, "Illegal input");
  std::vector<int64_t> vec(poly_degree_);
  std::copy(message.begin(), message.end(), vec.begin());
  return Plaintext(std::move(vec));
}

Plaintext BatchEncoder::EncodeT(absl::Span<const uint64_t> message) const {
  YACL_ENFORCE(message.size() <= poly_degree_, "Illegal input");
  std::vector<int64_t> vec(poly_degree_);
  std::copy(message.begin(), message.end(), vec.begin());
  return Plaintext(std::move(vec));
}

Plaintext BatchEncoder::EncodeT(absl::Span<const double>) const {
  YACL_THROW("BatchEncoder cannot encode float number");
}

Plaintext BatchEncoder::EncodeT(absl::Span<const std::complex<double>>) const {
  YACL_THROW("BatchEncoder cannot encode complex number");
}

Plaintext BatchEncoder::EncodeT(int64_t message) const {
  YACL_THROW("BatchEncode cannot encode a single scalar {}", message);
}

Plaintext BatchEncoder::EncodeT(uint64_t message) const {
  YACL_THROW("BatchEncode cannot encode a single scalar {}", message);
}

Plaintext BatchEncoder::EncodeT(double message) const {
  YACL_THROW("BatchEncode cannot encode a single scalar {}", message);
}

Plaintext BatchEncoder::EncodeT(const std::complex<double> &message) const {
  YACL_THROW("BatchEncode cannot encode a single scalar {}+{}i", message.real(),
             message.imag());
}

void BatchEncoder::DecodeT(const Plaintext &pt, absl::Span<int64_t> out) const {
  YACL_ENFORCE(out.size() >= poly_degree_,
               "Output space is not enough, cannot decode");
  std::copy(pt->begin(), pt->end(), out.begin());
}

void BatchEncoder::DecodeT(const Plaintext &pt,
                           absl::Span<uint64_t> out) const {
  YACL_ENFORCE(out.size() >= poly_degree_,
               "Output space is not enough, cannot decode");
  std::copy(pt->begin(), pt->end(), out.begin());
}

void BatchEncoder::DecodeT(const Plaintext &, absl::Span<double>) const {
  YACL_THROW("BatchEncoder does not support float number");
}

void BatchEncoder::DecodeT(const Plaintext &,
                           absl::Span<std::complex<double>>) const {
  YACL_THROW("BatchEncoder does not support complex number");
}

//==================================//
//             CkksEncoder          //
//==================================//

CkksEncoder::CkksEncoder(size_t poly_degree, int64_t scale) {
  YACL_ENFORCE(poly_degree % 2 == 0, "illegal degree {}", poly_degree);
  half_degree_ = poly_degree / 2;
  scale_ = scale;
}

size_t CkksEncoder::SlotCount() const { return half_degree_; }

std::string CkksEncoder::ToString() const {
  return fmt::format("CkksEncoder from mock_fhe lib, slot={}", half_degree_);
}

Plaintext CkksEncoder::FromStringT(std::string_view) const {
  YACL_THROW("mock_fhe: directly parse from string not implemented");
}

Plaintext CkksEncoder::EncodeT(absl::Span<const int64_t> message) const {
  YACL_ENFORCE(message.size() <= half_degree_, "Illegal input");
  std::vector<int64_t> vec(half_degree_ * 2);
  for (size_t i = 0; i < message.size(); ++i) {
    vec[i] = message[i] * scale_;
  }
  return Plaintext(std::move(vec), scale_);
}

Plaintext CkksEncoder::EncodeT(absl::Span<const uint64_t> message) const {
  YACL_ENFORCE(message.size() <= half_degree_, "Illegal input");
  std::vector<int64_t> vec(half_degree_ * 2);
  for (size_t i = 0; i < message.size(); ++i) {
    vec[i] = message[i] * scale_;
  }
  return Plaintext(std::move(vec), scale_);
}

Plaintext CkksEncoder::EncodeT(absl::Span<const double> message) const {
  YACL_ENFORCE(message.size() <= half_degree_, "Illegal input");
  std::vector<int64_t> vec(half_degree_ * 2);
  for (size_t i = 0; i < message.size(); ++i) {
    // Fix rounding (+/- 0.5)
    vec[i] = message[i] * scale_ + (message[i] >= 0 ? .5 : -.5);
  }
  return Plaintext(std::move(vec), scale_);
}

Plaintext CkksEncoder::EncodeT(
    absl::Span<const std::complex<double>> message) const {
  YACL_ENFORCE(message.size() <= half_degree_, "Illegal input");
  std::vector<int64_t> vec(half_degree_ * 2);
  for (size_t i = 0; i < message.size(); ++i) {
    // Fix rounding (+/- 0.5)
    vec[i] = message[i].real() * scale_ + (message[i].real() >= 0 ? .5 : -.5);
    vec[i + half_degree_] =
        message[i].imag() * scale_ + (message[i].imag() >= 0 ? .5 : -.5);
  }
  return Plaintext(std::move(vec), scale_);
}

Plaintext CkksEncoder::EncodeT(int64_t message) const {
  std::vector<int64_t> vec(half_degree_, message * scale_);
  vec.resize(half_degree_ * 2);
  return Plaintext(std::move(vec), scale_);
}

Plaintext CkksEncoder::EncodeT(uint64_t message) const {
  std::vector<int64_t> vec(half_degree_, message * scale_);
  vec.resize(half_degree_ * 2);
  return Plaintext(std::move(vec), scale_);
}

Plaintext CkksEncoder::EncodeT(double message) const {
  // Fix rounding (+/- 0.5)
  std::vector<int64_t> vec(half_degree_,
                           message * scale_ + (message >= 0 ? .5 : -.5));
  vec.resize(half_degree_ * 2);
  return Plaintext(std::move(vec), scale_);
}

Plaintext CkksEncoder::EncodeT(const std::complex<double> &message) const {
  // Encodes a double-precision complex number into a plaintext polynomial.
  // Append zeros to fill all slots.
  std::vector<int64_t> vec(half_degree_ * 2);
  // Fix rounding (+/- 0.5)
  vec[0] = message.real() * scale_ + (message.real() >= 0 ? .5 : -.5);
  vec[half_degree_] =
      message.imag() * scale_ + (message.imag() >= 0 ? .5 : -.5);
  return Plaintext(std::move(vec), scale_);
}

void CkksEncoder::DecodeT(const Plaintext &pt, absl::Span<int64_t> out) const {
  YACL_ENFORCE_GE(out.size(), half_degree_,
                  "Output space is not enough, cannot decode");
  YACL_ENFORCE_EQ(pt->size(), half_degree_ * 2, "illegal plaintext");
  for (size_t i = 0; i < half_degree_; ++i) {
    out[i] = pt.array_[i] / pt.scale_;
  }
}

void CkksEncoder::DecodeT(const Plaintext &pt, absl::Span<uint64_t> out) const {
  YACL_ENFORCE_GE(out.size(), half_degree_,
                  "Output space is not enough, cannot decode");
  YACL_ENFORCE_EQ(pt->size(), half_degree_ * 2, "illegal plaintext");
  for (size_t i = 0; i < half_degree_; ++i) {
    out[i] = pt.array_[i] / pt.scale_;
  }
}

void CkksEncoder::DecodeT(const Plaintext &pt, absl::Span<double> out) const {
  YACL_ENFORCE_GE(out.size(), half_degree_,
                  "Output space is not enough, cannot decode");
  YACL_ENFORCE_EQ(pt->size(), half_degree_ * 2, "illegal plaintext");
  for (size_t i = 0; i < half_degree_; ++i) {
    out[i] = static_cast<double>(pt.array_[i]) / pt.scale_;
  }
}

void CkksEncoder::DecodeT(const Plaintext &pt,
                          absl::Span<std::complex<double>> out) const {
  YACL_ENFORCE_GE(out.size(), half_degree_,
                  "Output space is not enough, cannot decode");
  YACL_ENFORCE_EQ(pt->size(), half_degree_ * 2, "illegal plaintext");
  for (size_t i = 0; i < half_degree_; ++i) {
    out[i] = std::complex<double>(
        static_cast<double>(pt.array_[i]) / pt.scale_,
        static_cast<double>(pt.array_[i + half_degree_]) / pt.scale_);
  }
}

}  // namespace heu::algos::mock_fhe
