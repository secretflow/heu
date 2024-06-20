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
#include <cstddef>
#include <string>
#include <string_view>
#include <type_traits>

#include "absl/types/span.h"
#include "yacl/base/int128.h"

#include "heu/spi/he/sketches/common/batch_encoder.h"

namespace heu::spi {

// Encode multiple cleartexts into one plaintext.
// Plaintext = (Cleartext1 * Scale | Cleartext2 * Scale | ...)
// Illustration:
//                                  Plaintext
//                       (max_slots = 3, padding_bits=32)
// +-----------------+---------+-----------------+---------+-----------------+
// | cleartext*scale | padding | cleartext*scale | padding | cleartext*scale |
// +-----------------+---------+-----------------+---------+-----------------+
//       64 bits       32 bits       64 bits       32 bits       64 bits
//
// Out-of-the-box implementation, generally no inheritance required
template <typename PlaintextT>
class ScaledBatchEncoder : public BatchEncoderSketch<PlaintextT> {
 public:
  using SlotT = uint64_t;  // plaintext slots' real type. must be unsigned types

  // During batch encoding, if the lower digits overflow, the upper digits will
  // be affected. The suggested 32-bit padding supports approximately 2 billion
  // addition operations
  ScaledBatchEncoder(int64_t scale, size_t max_plaintext_bits,
                     size_t padding_bits)
      : scale_(scale), padding_bits_(padding_bits) {
    static_assert(std::is_unsigned_v<SlotT>,
                  "Cleartext must be an unsigned type");
    YACL_ENFORCE(scale > 0, "unsupported scale = {}", scale);
    max_slot_ = (max_plaintext_bits + padding_bits) /
                (sizeof(SlotT) * CHAR_BIT + padding_bits);
  }

  size_t SlotCount() const override { return max_slot_; }

  std::string ToString() const override {
    return fmt::format("BatchEncoder(scale={}, max_batch={}, padding_bits={})",
                       scale_, max_slot_, padding_bits_);
  }

  PlaintextT FromStringT(std::string_view pt_str) const override {
    return PlaintextT((std::string)pt_str);
  }

  //===   vector encode   ===//

  // The size of the message is always in [1, SlotCount()]
  PlaintextT EncodeT(absl::Span<const int64_t> message) const override {
    return DoEncodeT(message, [this](int64_t v) -> SlotT {
      auto sv = static_cast<std::make_signed<SlotT>::type>(v * scale_);
      // get the underlying raw bits without a convert. (in 2's complement code)
      return *reinterpret_cast<SlotT *>(&sv);
    });
  }

  // The size of the message is always in [1, SlotCount()]
  PlaintextT EncodeT(absl::Span<const uint64_t> message) const override {
    return DoEncodeT(message, [this](uint64_t v) -> SlotT {
      return static_cast<SlotT>(v * static_cast<uint64_t>(scale_));
    });
  }

  // The size of the message is always in [1, SlotCount()]
  PlaintextT EncodeT(absl::Span<const double> message) const override {
    return DoEncodeT(message, [this](double v) -> SlotT {
      // Fix rounding (+/- 0.5)
      auto sv = static_cast<std::make_signed<SlotT>::type>(v * scale_ +
                                                           (v >= 0 ? .5 : -.5));
      // get the underlying raw bits without a convert. (in 2's complement code)
      return *reinterpret_cast<SlotT *>(&sv);
    });
  }

  // The size of the message is always in [1, SlotCount()]
  PlaintextT EncodeT(absl::Span<const std::complex<double>>) const override {
    YACL_THROW("ScaledBatchEncoder do not support encode complex number");
  }

  //===   Scalar encode   ===//

  PlaintextT EncodeT(int64_t message) const override {
    return PlaintextT(message * scale_);
  }

  PlaintextT EncodeT(uint64_t message) const override {
    return PlaintextT(message * scale_);
  }

  PlaintextT EncodeT(double message) const override {
    // Fix rounding (+/- 0.5)
    return PlaintextT(message * scale_ + (message >= 0 ? .5 : -.5));
  }

  PlaintextT EncodeT(const std::complex<double> &) const override {
    YACL_THROW("ScaledBatchEncoder do not support encode complex number");
  }

  //===   Vector decode   ===//

  void DecodeT(const PlaintextT &pt, absl::Span<int64_t> out) const override {
    DoDecodeT<std::make_signed<SlotT>::type>(pt, out);
  }

  void DecodeT(const PlaintextT &pt, absl::Span<uint64_t> out) const override {
    DoDecodeT<SlotT>(pt, out);
  }

  void DecodeT(const PlaintextT &pt, absl::Span<double> out) const override {
    DoDecodeT<std::make_signed<SlotT>::type>(pt, out);
  }

  void DecodeT(const PlaintextT &,
               absl::Span<std::complex<double>>) const override {
    YACL_THROW("ScaledBatchEncoder do not support decode complex number");
  }

 private:
  template <typename InputT, typename F>
  PlaintextT DoEncodeT(absl::Span<const InputT> message,
                       const F &convert_func) const {
    auto m_sz = message.size();
    YACL_ENFORCE(m_sz > 0 && m_sz <= max_slot_);
    auto total_bits =
        sizeof(SlotT) * CHAR_BIT * m_sz + padding_bits_ * (m_sz - 1);
    int64_t idx = m_sz - 1;
    PlaintextT pt(convert_func(message[idx]), total_bits);
    PlaintextT tmp;
    while (--idx >= 0) {
      pt <<= sizeof(SlotT) * CHAR_BIT + padding_bits_;
      tmp.Set(convert_func(message[idx]));
      pt |= tmp;
    }
    return pt;
  }

  template <typename SlotViewT, typename OutT>
  void DoDecodeT(PlaintextT pt, absl::Span<OutT> out) const {
    YACL_ENFORCE(out.size() >= max_slot_);
    for (size_t i = 0; i < max_slot_; ++i) {
      out[i] = pt.template Get<SlotViewT>() / static_cast<OutT>(scale_);
      pt >>= sizeof(SlotT) * CHAR_BIT + padding_bits_;
    }
  }

  int64_t scale_;
  size_t max_slot_;
  size_t padding_bits_;
};

}  // namespace heu::spi
