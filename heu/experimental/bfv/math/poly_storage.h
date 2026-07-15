#ifndef POLY_STORAGE_H
#define POLY_STORAGE_H

#include <memory>

#include "math/poly.h"

namespace bfv::math::rq {

class Poly::Impl {
 public:
  std::shared_ptr<const Context> ctx;
  Representation representation;
  bool has_lazy_coefficients;
  bool allow_variable_time_computations;

  ::bfv::util::ArenaHandle pool;
  ::bfv::util::Pointer<uint64_t> coefficients;
  ::bfv::util::Pointer<uint64_t> coefficients_shoup;

  explicit Impl(
      ::bfv::util::ArenaHandle pool_ = ::bfv::util::ArenaHandle::Shared());
  ~Impl();

  Impl(const Impl &other);
  Impl &operator=(const Impl &other);
  Impl(Impl &&other) noexcept;
  Impl &operator=(Impl &&other) noexcept;

  void clear_multiply_hints();
  void rebuild_multiply_hints();
  void ntt_forward();
  void ntt_backward();
};

}  // namespace bfv::math::rq

#endif
