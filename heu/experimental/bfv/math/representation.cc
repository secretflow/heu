#include "math/representation.h"

#include <stdexcept>

namespace bfv::math::rq {

const char *representation_to_string(Representation repr) {
  switch (repr) {
    case Representation::PowerBasis:
      return "PowerBasis";
    case Representation::Ntt:
      return "Ntt";
    case Representation::NttShoup:
      return "NttShoup";
    default:
      return "Unknown";
  }
}

Representation representation_from_string(const std::string &str) {
  if (str == "PowerBasis") {
    return Representation::PowerBasis;
  } else if (str == "Ntt") {
    return Representation::Ntt;
  } else if (str == "NttShoup") {
    return Representation::NttShoup;
  } else {
    throw std::invalid_argument("Unknown representation: " + str);
  }
}

}  // namespace bfv::math::rq
