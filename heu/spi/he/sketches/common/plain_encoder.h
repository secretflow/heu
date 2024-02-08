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

#include <vector>

#include "heu/spi/he/sketches/common/encoder.h"

namespace heu::lib::spi {

template <typename PlaintextT>
class PlainEncoderSketch : public EncoderSketch<PlaintextT> {
 public:
  size_t SlotCount() const override { return 1; }

  virtual PlaintextT EncodeT(int64_t message) const = 0;
  virtual PlaintextT EncodeT(uint64_t message) const = 0;
  virtual PlaintextT EncodeT(double message) const = 0;
  virtual PlaintextT EncodeT(const std::complex<double> &message) const = 0;

  virtual void DecodeT(const PlaintextT &pt, int64_t *out) const = 0;
  virtual void DecodeT(const PlaintextT &pt, uint64_t *out) const = 0;
  virtual void DecodeT(const PlaintextT &pt, double *out) const = 0;
  virtual void DecodeT(const PlaintextT &pt,
                       std::complex<double> *out) const = 0;

 private:
  template <typename T>
  Item CallEncoderT(const absl::Span<T> &message) const {
    std::vector<PlaintextT> res(message.size());
    auto in = message.data();
    yacl::parallel_for(0, message.size(), 1, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        res.at(i) = EncodeT(in[i]);
      }
    });
    return {std::move(res), ContentType::Plaintext};
  }

  Item Encode(absl::Span<const int64_t> message) const override {
    return CallEncoderT(message);
  }

  Item Encode(absl::Span<const uint64_t> message) const override {
    return CallEncoderT(message);
  }

  Item Encode(absl::Span<const double> message) const override {
    return CallEncoderT(message);
  }

  Item Encode(absl::Span<const std::complex<double>> message) const override {
    return CallEncoderT(message);
  }

  template <typename T>
  void CallDecodeT(const Item &pts, absl::Span<T> out) const {
    auto sp = pts.AsSpan<PlaintextT>();
    YACL_ENFORCE(out.size() >= sp.size(),
                 "There is not enough space to store all decoded numbers. "
                 "min_required={}, span_len={}",
                 sp.size(), out.size());

    auto in = sp.data();
    auto buf = out.data();
    yacl::parallel_for(0, sp.size(), 1, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        DecodeT(in[i], buf + i);
      }
    });
  }

  void Decode(const Item &plaintexts,
              absl::Span<int64_t> out_message) const override {
    CallDecodeT(plaintexts, out_message);
  }

  void Decode(const Item &plaintexts,
              absl::Span<uint64_t> out_message) const override {
    CallDecodeT(plaintexts, out_message);
  }

  void Decode(const Item &plaintexts,
              absl::Span<double> out_message) const override {
    CallDecodeT(plaintexts, out_message);
  }

  void Decode(const Item &plaintexts,
              absl::Span<std::complex<double>> out_message) const override {
    CallDecodeT(plaintexts, out_message);
  }

  std::vector<int64_t> DecodeInt64(const Item &plaintexts) const override {
    std::vector<int64_t> res(plaintexts.Size<PlaintextT>());
    CallDecodeT(plaintexts, absl::MakeSpan(res));
    return res;
  }

  std::vector<uint64_t> DecodeUint64(const Item &plaintexts) const override {
    std::vector<uint64_t> res(plaintexts.Size<PlaintextT>());
    CallDecodeT(plaintexts, absl::MakeSpan(res));
    return res;
  }

  std::vector<double> DecodeDouble(const Item &plaintexts) const override {
    std::vector<double> res(plaintexts.Size<PlaintextT>());
    CallDecodeT(plaintexts, absl::MakeSpan(res));
    return res;
  }

  std::vector<std::complex<double>> DecodeComplex(
      const Item &plaintexts) const override {
    std::vector<std::complex<double>> res(plaintexts.Size<PlaintextT>());
    CallDecodeT(plaintexts, absl::MakeSpan(res));
    return res;
  }

  // ===  Special functions for PlainEncoder  === //

  Item EncodeScalar(int64_t message) const override {
    return {EncodeT(message), ContentType::Plaintext};
  }

  Item EncodeScalar(uint64_t message) const override {
    return {EncodeT(message), ContentType::Plaintext};
  }

  Item EncodeScalar(double message) const override {
    return {EncodeT(message), ContentType::Plaintext};
  }

  Item EncodeScalar(const std::complex<double> &message) const override {
    return {EncodeT(message), ContentType::Plaintext};
  }

  template <typename T>
  void CallDecodeScalarT(const Item &pt, T *out) const {
    YACL_ENFORCE(pt.Size<PlaintextT>() == 1,
                 "The plaintext contains more than one cleartext, cannot "
                 "decode as a scalar, GetCleartextCount(pt)={}",
                 this->GetCleartextCount(pt));

    if (pt.DataTypeIs<PlaintextT>()) {
      DecodeT(pt.As<PlaintextT>(), out);
    } else {
      DecodeT(pt.AsSpan<PlaintextT>()[0], out);
    }
  }

  // Decode single cleartext.
  // Must have GetCleartextCount(plaintext) == 1.
  int64_t DecodeScalarInt64(const Item &plaintext) const override {
    int64_t res;
    CallDecodeScalarT(plaintext, &res);
    return res;
  }

  uint64_t DecodeScalarUint64(const Item &plaintext) const override {
    uint64_t res;
    CallDecodeScalarT(plaintext, &res);
    return res;
  }

  double DecodeScalarDouble(const Item &plaintext) const override {
    double res;
    CallDecodeScalarT(plaintext, &res);
    return res;
  }

  std::complex<double> DecodeScalarComplex(
      const Item &plaintext) const override {
    std::complex<double> res;
    CallDecodeScalarT(plaintext, &res);
    return res;
  }
};

}  // namespace heu::lib::spi
