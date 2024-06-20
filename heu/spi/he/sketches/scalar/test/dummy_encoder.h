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

#include <string>

#include "heu/spi/he/sketches/common/batch_encoder.h"
#include "heu/spi/he/sketches/common/plain_encoder.h"
#include "heu/spi/he/sketches/scalar/test/dummy_ops.h"

namespace heu::spi::test {

class DummyPlainEncoder : public PlainEncoderSketch<DummyPt> {
 public:
  std::string ToString() const override { return "DummyPlainEncoder"; }

  DummyPt FromStringT(std::string_view pt_str) const override {
    return DummyPt((std::string)pt_str);
  }

  DummyPt EncodeT(int64_t message) const override {
    return DummyPt(fmt::format("Encode({})", message));
  }

  DummyPt EncodeT(uint64_t message) const override {
    return DummyPt(fmt::format("Encode({})", message));
  }

  DummyPt EncodeT(double message) const override {
    return DummyPt(fmt::format("Encode({})", message));
  }

  DummyPt EncodeT(const std::complex<double> &message) const override {
    return DummyPt(
        fmt::format("Encode({} + {}i)", message.real(), message.imag()));
  }

  void DecodeT(const DummyPt &, int64_t *out) const override { *out = 44; }

  void DecodeT(const DummyPt &, uint64_t *out) const override { *out = 48; }

  void DecodeT(const DummyPt &, double *out) const override { *out = 52; }

  void DecodeT(const DummyPt &, std::complex<double> *out) const override {
    using namespace std::complex_literals;
    *out = 57i;
  }
};

class DummyBatchEncoder : public BatchEncoderSketch<DummyPt> {
 public:
  explicit DummyBatchEncoder(size_t max_slot) : max_slot_(max_slot) {}

  size_t SlotCount() const override { return max_slot_; }

  std::string ToString() const override { return "DummyBatchEncoder"; }

  DummyPt FromStringT(std::string_view pt_str) const override {
    return DummyPt((std::string)pt_str);
  }

  DummyPt EncodeT(absl::Span<const int64_t> message) const override {
    // Test: The size of the message is always in [1, SlotCount()]
    // DO NOT use YACL_ENFORCE here, since we will test EXPECT_ANY_THROW outer.
    EXPECT_TRUE(message.size() > 0);
    EXPECT_TRUE(message.size() <= max_slot_);
    return DummyPt(fmt::format("Encode({})", fmt::join(message, ", ")));
  }

  DummyPt EncodeT(absl::Span<const uint64_t> message) const override {
    // DO NOT use YACL_ENFORCE here, since we will test EXPECT_ANY_THROW outer.
    EXPECT_TRUE(message.size() > 0 && message.size() <= max_slot_);
    return DummyPt(fmt::format("Encode({})", fmt::join(message, ", ")));
  }

  DummyPt EncodeT(absl::Span<const double> message) const override {
    // DO NOT use YACL_ENFORCE here, since we will test EXPECT_ANY_THROW outer.
    EXPECT_TRUE(message.size() > 0 && message.size() <= max_slot_);
    return DummyPt(fmt::format("Encode({})", fmt::join(message, ", ")));
  }

  DummyPt EncodeT(
      absl::Span<const std::complex<double>> message) const override {
    // DO NOT use YACL_ENFORCE here, since we will test EXPECT_ANY_THROW outer.
    EXPECT_TRUE(message.size() > 0 && message.size() <= max_slot_);
    return DummyPt(fmt::format("Encode(complex{})", message.size()));
  }

  DummyPt EncodeT(int64_t message) const override {
    return EncodeT(std::vector<int64_t>(max_slot_, message));
  }

  DummyPt EncodeT(uint64_t message) const override {
    return EncodeT(std::vector<uint64_t>(max_slot_, message));
  }

  DummyPt EncodeT(double message) const override {
    return EncodeT(std::vector<double>(max_slot_, message));
  }

  DummyPt EncodeT(const std::complex<double> &message) const override {
    return EncodeT(std::vector<std::complex<double>>(max_slot_, message));
  }

  void DecodeT(const DummyPt &, absl::Span<int64_t> out) const override {
    YACL_ENFORCE(out.size() >= max_slot_);
    for (size_t i = 0; i < max_slot_; ++i) {
      out[i] = i + 96;
    }
  }

  void DecodeT(const DummyPt &, absl::Span<uint64_t> out) const override {
    YACL_ENFORCE(out.size() >= max_slot_);
    for (size_t i = 0; i < max_slot_; ++i) {
      out[i] = i + 103;
    }
  }

  void DecodeT(const DummyPt &, absl::Span<double> out) const override {
    YACL_ENFORCE(out.size() >= max_slot_);
    for (size_t i = 0; i < max_slot_; ++i) {
      out[i] = i + 110.;
    }
  }

  void DecodeT(const DummyPt &,
               absl::Span<std::complex<double>> out) const override {
    YACL_ENFORCE(out.size() >= max_slot_);
    for (size_t i = 0; i < max_slot_; ++i) {
      out[i] = i + 118;
    }
  }

 private:
  size_t max_slot_;
};

}  // namespace heu::spi::test
