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

#include "heu/spi/he/item.h"

#include <cstdint>
#include <string>

static constexpr int kContentSlot = 5;
static constexpr int kContentSlotLen = 3;

namespace heu::lib::spi {

void Item::MarkAs(ContentType type) {
  SetSlot<kContentSlot, kContentSlotLen>(static_cast<uint8_t>(type));
}

void Item::MarkAsCiphertext() { MarkAs(ContentType::Ciphertext); }

void Item::MarkAsPlaintext() { MarkAs(ContentType::Plaintext); }

ContentType Item::GetContentType() const {
  return static_cast<ContentType>(GetSlot<kContentSlot, kContentSlotLen>());
}

bool Item::IsPlaintext() const {
  return GetContentType() == ContentType::Plaintext;
}

bool Item::IsCiphertext() const {
  return GetContentType() == ContentType::Ciphertext;
}

std::string Item::ToString() const {
  return fmt::format("ContentType={} {}", GetContentType(),
                     yacl::Item::ToString());
}

std::ostream &operator<<(std::ostream &os, const Item &item) {
  return os << item.ToString();
}

}  // namespace heu::lib::spi
