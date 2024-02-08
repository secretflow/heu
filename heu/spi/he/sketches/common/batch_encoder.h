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
class BatchEncoderSketch : public EncoderSketch<PlaintextT> {
 public:
  // Functions to override:
  //   virtual size_t SlotCount() const = 0;

  // The size of the message is always in [0, SlotCount())
  // So there is enough space to encode message into one plaintext
  virtual PlaintextT EncodeT(absl::Span<const int64_t> message) const = 0;
  virtual PlaintextT EncodeT(absl::Span<const uint64_t> message) const = 0;
  virtual PlaintextT EncodeT(absl::Span<const double> message) const = 0;
  virtual PlaintextT EncodeT(
      absl::Span<const std::complex<double>> message) const = 0;

  virtual void DecodeT(const PlaintextT& pt, absl::Span<int64_t> out) const = 0;
  virtual void DecodeT(const PlaintextT& pt,
                       absl::Span<uint64_t> out) const = 0;
  virtual void DecodeT(const PlaintextT& pt, absl::Span<double> out) const = 0;
  virtual void DecodeT(const PlaintextT& pt,
                       absl::Span<std::complex<double>> out) const = 0;

 private:
  template <typename T>
  Item CallEncoderT(const absl::Span<T>& message) const {
    auto slots = this->SlotCount();
    if (message.size() <= slots) {
      return {EncodeT(message), ContentType::Plaintext};
    }

    auto pts = (message.size() + slots - 1) / slots;
    std::vector<PlaintextT> res(pts);
    yacl::parallel_for(0, pts, 1, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        res.at(i) = EncodeT(message.subspan(slots * i, slots));
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
  void CallDecodeT(const Item& pts, absl::Span<T> out) const {
    auto sp = pts.AsSpan<PlaintextT>();
    auto slots = this->SlotCount();
    auto total = sp.size() * slots;
    YACL_ENFORCE(out.size() >= total,
                 "There is not enough space to store all decoded numbers. "
                 "min_required={}, span_len={}",
                 total, out.size());

    auto in = sp.data();
    yacl::parallel_for(0, sp.size(), 1, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        DecodeT(in[i], out.subspan(slots * i, slots));
      }
    });
  }

  void Decode(const Item& plaintexts,
              absl::Span<int64_t> out_message) const override {
    CallDecodeT(plaintexts, out_message);
  }

  void Decode(const Item& plaintexts,
              absl::Span<uint64_t> out_message) const override {
    CallDecodeT(plaintexts, out_message);
  }

  void Decode(const Item& plaintexts,
              absl::Span<double> out_message) const override {
    CallDecodeT(plaintexts, out_message);
  }

  void Decode(const Item& plaintexts,
              absl::Span<std::complex<double>> out_message) const override {
    CallDecodeT(plaintexts, out_message);
  }

  std::vector<int64_t> DecodeInt64(const Item& plaintexts) const override {
    std::vector<int64_t> res(this->GetCleartextCount(plaintexts));
    CallDecodeT(plaintexts, absl::MakeSpan(res));
    return res;
  }

  std::vector<uint64_t> DecodeUint64(const Item& plaintexts) const override {
    std::vector<uint64_t> res(this->GetCleartextCount(plaintexts));
    CallDecodeT(plaintexts, absl::MakeSpan(res));
    return res;
  }

  std::vector<double> DecodeDouble(const Item& plaintexts) const override {
    std::vector<double> res(this->GetCleartextCount(plaintexts));
    CallDecodeT(plaintexts, absl::MakeSpan(res));
    return res;
  }

  std::vector<std::complex<double>> DecodeComplex(
      const Item& plaintexts) const override {
    std::vector<std::complex<double>> res(this->GetCleartextCount(plaintexts));
    CallDecodeT(plaintexts, absl::MakeSpan(res));
    return res;
  }

  // ==================================================================== //
  // <<<  The following functions are only supported by PlainEncoder  >>> //
  // <<<       If you are using BatchEncoder, do not call them        >>> //
  // ==================================================================== //

  Item EncodeScalar(int64_t message) const override {
    YACL_THROW(
        "Batch encoder cannot encode scalar {}, please use Encode() "
        "instead.",
        message);
  }

  Item EncodeScalar(uint64_t message) const override {
    YACL_THROW(
        "Batch encoder cannot encode scalar {}, please use Encode() "
        "instead.",
        message);
  }

  Item EncodeScalar(double message) const override {
    YACL_THROW(
        "Batch encoder cannot encode scalar {}, please use Encode() "
        "instead.",
        message);
  }

  Item EncodeScalar(const std::complex<double>& message) const override {
    YACL_THROW(
        "Batch encoder cannot encode scalar {}+{}i, please use Encode() "
        "instead.",
        message.real(), message.imag());
  }

  int64_t DecodeScalarInt64(const Item& plaintext) const override {
    YACL_THROW(
        "Batch encoder cannot decode plaintext as a single number, please use "
        "Decode() instead. plaintext={}",
        plaintext);
  }

  uint64_t DecodeScalarUint64(const Item& plaintext) const override {
    YACL_THROW(
        "Batch encoder cannot decode plaintext as a single number, please use "
        "Decode() instead. plaintext={}",
        plaintext);
  }

  double DecodeScalarDouble(const Item& plaintext) const override {
    YACL_THROW(
        "Batch encoder cannot decode plaintext as a single number, please use "
        "Decode() instead. plaintext={}",
        plaintext);
  }

  std::complex<double> DecodeScalarComplex(
      const Item& plaintext) const override {
    YACL_THROW(
        "Batch encoder cannot decode plaintext as a single number, please use "
        "Decode() instead. plaintext={}",
        plaintext);
  }
};

}  // namespace heu::lib::spi
