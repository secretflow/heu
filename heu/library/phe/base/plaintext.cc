// Copyright 2022 Ant Group Co., Ltd.
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

#include "plaintext.h"

#include "heu/library/phe/base/variant_helper.h"

namespace heu::lib::phe {

void Plaintext::SetValue(const std::string& num, int radix) {
  Visit([&](auto& pt) { FOR_EACH_TYPE(pt) pt.Set(num, radix); });
}

size_t Plaintext::BitCount() const {
  return Visit([](const auto& pt) -> size_t {
    FOR_EACH_TYPE(pt) return pt.BitCount();
  });
}

yasl::Buffer Plaintext::ToBytes(size_t byte_len,
                                algorithms::Endian endian) const {
  return Visit([&](const auto& pt) -> yasl::Buffer {
    FOR_EACH_TYPE(pt) return pt.ToBytes(byte_len, endian);
  });
}

void Plaintext::ToBytes(unsigned char* buf, size_t buf_len,
                        algorithms::Endian endian) const {
  Visit([&](const auto& pt) {
    FOR_EACH_TYPE(pt) pt.ToBytes(buf, buf_len, endian);
  });
}

std::string Plaintext::ToHexString() const {
  return Visit([](const auto& clazz) -> std::string {
    FOR_EACH_TYPE(clazz) return clazz.ToHexString();
  });
}

#define OPERATOR_RET_IMPL(op, opb)                                       \
  Plaintext Plaintext::operator op(const Plaintext& operand2) const {    \
    return Visit([&](const auto& pt) -> Plaintext {                      \
      FOR_EACH_TYPE(pt) return Plaintext(pt op operand2.AsTypeLike(pt)); \
    });                                                                  \
  }                                                                      \
                                                                         \
  Plaintext Plaintext::operator opb(const Plaintext& operand2) {         \
    Visit([&](auto& pt) {                                                \
      FOR_EACH_TYPE(pt) pt opb operand2.AsTypeLike(pt);                  \
    });                                                                  \
    return *this;                                                        \
  }

OPERATOR_RET_IMPL(+, +=)
OPERATOR_RET_IMPL(-, -=)
OPERATOR_RET_IMPL(*, *=)
OPERATOR_RET_IMPL(/, /=)
OPERATOR_RET_IMPL(%, %=)
OPERATOR_RET_IMPL(&, &=)
OPERATOR_RET_IMPL(|, |=)
OPERATOR_RET_IMPL(^, ^=)

Plaintext Plaintext::operator<<(size_t operand2) const {
  return Visit([&](const auto& pt) -> Plaintext {
    FOR_EACH_TYPE(pt) return Plaintext(pt << operand2);
  });
}

Plaintext Plaintext::operator>>(size_t operand2) const {
  return Visit([&](const auto& pt) -> Plaintext {
    FOR_EACH_TYPE(pt) return Plaintext(pt >> operand2);
  });
}

Plaintext Plaintext::operator-() const {
  return Visit([&](const auto& pt) -> Plaintext {
    FOR_EACH_TYPE(pt) return Plaintext(-pt);
  });
}

void Plaintext::NegInplace() {
  Visit([&](auto& pt) { FOR_EACH_TYPE(pt) pt.NegInplace(); });
}

Plaintext Plaintext::operator<<=(size_t operand2) {
  Visit([&](auto& pt) { FOR_EACH_TYPE(pt) pt <<= operand2; });
  return *this;
}

Plaintext Plaintext::operator>>=(size_t operand2) {
  Visit([&](auto& pt) { FOR_EACH_TYPE(pt) pt >>= operand2; });
  return *this;
}

#define OPERATOR_BOOL_IMPL(op)                                \
  bool Plaintext::operator op(const Plaintext& other) const { \
    return var_ op other.var_;                                \
  }

OPERATOR_BOOL_IMPL(>)
OPERATOR_BOOL_IMPL(>=)
OPERATOR_BOOL_IMPL(<)
OPERATOR_BOOL_IMPL(<=)
OPERATOR_BOOL_IMPL(==)
OPERATOR_BOOL_IMPL(!=)

void Plaintext::RandomExactBits(SchemaType schema, size_t bit_size,
                                Plaintext* r) {
  if (!r->IsCompatible(schema)) {
    *r = Plaintext(schema);
  }

  r->Visit([&](auto& ir) {
    FOR_EACH_TYPE(ir) ir.RandomExactBits(bit_size, &ir);
  });
}

void Plaintext::RandomLtN(const Plaintext& n, Plaintext* r) {
  if (r->var_.index() != n.var_.index()) {
    r->EmplaceInstance(n.var_.index());
  }

  r->Visit([&](auto& ir) {
    FOR_EACH_TYPE(ir) ir.RandomLtN(n.template AsTypeLike(ir), &ir);
  });
}

}  // namespace heu::lib::phe
