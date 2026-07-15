#include "crypto/encoding.h"

#include <sstream>

namespace crypto {
namespace bfv {

// Encoding::Impl - PIMPL implementation
class Encoding::Impl {
 public:
  EncodingType encoding_type;
  size_t level;

  Impl(EncodingType type, size_t lvl) : encoding_type(type), level(lvl) {}
};

// Encoding implementation
Encoding::Encoding() : pImpl(std::make_unique<Impl>(EncodingType::Poly, 0)) {}

Encoding::~Encoding() = default;

Encoding::Encoding(const Encoding &other)
    : pImpl(std::make_unique<Impl>(*other.pImpl)) {}

Encoding &Encoding::operator=(const Encoding &other) {
  if (this != &other) {
    pImpl = std::make_unique<Impl>(*other.pImpl);
  }
  return *this;
}

Encoding::Encoding(Encoding &&other) noexcept = default;
Encoding &Encoding::operator=(Encoding &&other) noexcept = default;

Encoding::Encoding(EncodingType type, size_t level)
    : pImpl(std::make_unique<Impl>(type, level)) {}

// Factory methods
Encoding Encoding::poly() { return Encoding(EncodingType::Poly, 0); }

Encoding Encoding::simd() { return Encoding(EncodingType::Simd, 0); }

Encoding Encoding::poly_at_level(size_t level) {
  return Encoding(EncodingType::Poly, level);
}

Encoding Encoding::simd_at_level(size_t level) {
  return Encoding(EncodingType::Simd, level);
}

// Accessors
EncodingType Encoding::encoding_type() const { return pImpl->encoding_type; }

size_t Encoding::level() const { return pImpl->level; }

// Comparison operators
bool Encoding::operator==(const Encoding &other) const {
  return pImpl->encoding_type == other.pImpl->encoding_type &&
         pImpl->level == other.pImpl->level;
}

bool Encoding::operator!=(const Encoding &other) const {
  return !(*this == other);
}

// String conversion
std::string Encoding::to_string() const {
  std::ostringstream oss;
  oss << "Encoding { encoding: ";

  switch (pImpl->encoding_type) {
    case EncodingType::Poly:
      oss << "Poly";
      break;
    case EncodingType::Simd:
      oss << "Simd";
      break;
  }

  oss << ", level: " << pImpl->level << " }";
  return oss.str();
}

}  // namespace bfv
}  // namespace crypto
