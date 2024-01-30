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

#include "heu/spi/he/base.h"

static constexpr int kCipherSlot = 7;

namespace heu::lib::spi {

// Slot 7: Ciphertext = 1(true), Plaintext = 0(false);
void Item::MarkAs(ItemType cipher_or_plain) {
  SetSlot<kCipherSlot>(cipher_or_plain == ItemType::Ciphertext);
}

void Item::MarkAsCiphertext() { SetSlot<kCipherSlot>(true); }

void Item::MarkAsPlaintext() { SetSlot<kCipherSlot>(false); }

bool Item::IsPlaintext() const { return !GetSlot<kCipherSlot>(); }

bool Item::IsCiphertext() const { return GetSlot<kCipherSlot>(); }

std::string Item::ToString() const {
  return fmt::format("{} {}", IsCiphertext() ? "Ciphertext" : "Plaintext",
                     yacl::Item::ToString());
}

}  // namespace heu::lib::spi
