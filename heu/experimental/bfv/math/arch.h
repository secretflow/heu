#ifndef ARCH_H
#define ARCH_H

#include <functional>

class Arch {
 public:
  Arch() {}

  template <typename F>
  void dispatch(F f) const {
#pragma omp parallel
    {
      f();
    }
  }
};

#endif
