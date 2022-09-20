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

#include "pybind11/pybind11.h"

#include "heu/pylib/numpy_binding/bind_numpy.h"
#include "heu/pylib/phe_binding/bind_encoder.h"
#include "heu/pylib/phe_binding/bind_phe.h"

namespace heu::pylib {

PYBIND11_MODULE(heu, m) {
  m.doc() =
      "Homomorphic Encryption processing Unit (HEU) is a subproject of "
      "Secretflow that implements high-performance homomorphic encryption "
      "algorithms.";

  auto phe = m.def_submodule(
      "phe", "A high-performance partial homomorphic encryption library");
  PyBindPhe(phe);
  PyBindEncoders(phe);

  auto hnp = m.def_submodule(
      "numpy", "a numpy adapter for phe module which provides numpy-like api");
  PyBindNumpy(hnp);
}

}  // namespace heu::pylib
