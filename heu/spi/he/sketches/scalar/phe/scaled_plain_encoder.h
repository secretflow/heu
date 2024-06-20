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

#include "yacl/base/int128.h"

#include "heu/spi/he/sketches/common/plain_encoder.h"

namespace heu::spi {

// A simple plain encoder implementation.
// Way of working: plaintext = cleartext * scale
// Out-of-the-box implementation, generally no inheritance required
template <typename PlaintextT>
class ScaledPlainEncoder : public PlainEncoderSketch<PlaintextT> {
 public:
  explicit ScaledPlainEncoder(int128_t scale) : scale_(scale) {}

  std::string ToString() const override {
    return fmt::format("ScaledPlainEncoder(scale={})", scale_);
  }

  PlaintextT FromStringT(std::string_view pt_str) const override {
    return PlaintextT((std::string)pt_str);
  }

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
    YACL_THROW("ScaledPlainEncoder do not support encode complex number");
  }

  void DecodeT(const PlaintextT &m, int64_t *out) const override {
    *out = m.template Get<int128_t>() / scale_;
  }

  void DecodeT(const PlaintextT &m, uint64_t *out) const override {
    *out = m.template Get<uint128_t>() / scale_;
  }

  void DecodeT(const PlaintextT &m, double *out) const override {
    *out = m.template Get<double>() / scale_;
  }

  void DecodeT(const PlaintextT &, std::complex<double> *) const override {
    YACL_THROW("ScaledPlainEncoder do not support decode complex number");
  }

 private:
  int128_t scale_ = 0;
};

}  // namespace heu::spi
