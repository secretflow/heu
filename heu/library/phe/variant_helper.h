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

#pragma once

namespace heu::lib::phe {

// functions with 1 args //

#define HE_METHOD_T1_VOID(ns, clazz, func, type1, out1) \
  [&](const ns::clazz& eval) { eval.func(&out1->get<ns::type1>()); }

#define HE_METHOD_T1_RET(ns, clazz, ret, func, type1, in1) \
  [&](const ns::clazz& eval) -> ret {                      \
    return ret(eval.func(in1.get<ns::type1>()));           \
  }

// functions with 2 args //

#define HE_METHOD_T1_T2_VOID(ns, clazz, func, type1, out1, type2, in2) \
  [&](const ns::clazz& eval) {                                         \
    eval.func(&out1->get<ns::type1>(), in2.get<ns::type2>());          \
  }

#define HE_METHOD_T1_T2_RET(ns, clazz, ret, func, type1, in1, type2, in2) \
  [&](const ns::clazz& eval) -> ret {                                     \
    return ret(eval.func(in1.get<ns::type1>(), in2.get<ns::type1>()));    \
  }

#define HE_METHOD_T1_MPINT_VOID(ns, clazz, func, type1, out1, mpint_var) \
  [&](const ns::clazz& eval) { eval.func(&out1->get<ns::type1>(), mpint_var); }

#define HE_METHOD_T1_MPINT_RET(ns, clazz, ret, func, type1, in1, mpint_var) \
  [&](const ns::clazz& eval) -> ret {                                       \
    return ret(eval.func(in1.get<ns::type1>(), mpint_var));                 \
  }

#define HE_METHOD_MPINT_T2_RET(ns, clazz, ret, func, mpint_var, type2, in2) \
  [&](const ns::clazz& eval) -> ret {                                       \
    return ret(eval.func(mpint_var, in2.get<ns::type2>()));                 \
  }

// others //

// borrowed from https://en.cppreference.com/w/cpp/utility/variant/visit
// `Overloaded` is a helper class required by std::visit() to bind a set of
// lambdas to the overloaded operators(type), one for each specific subtype
// (e.g. paillier_z::Encryptor).
// [Complexity] std::visit() can call the corresponding lambda according to the
// stored type in O(1) time since the input number of variants is always one
template <class... Ts>
struct Overloaded : Ts... {
  using Ts::operator()...;
};
// explicit deduction guide (not needed as of C++20)
template <class... Ts>
Overloaded(Ts...) -> Overloaded<Ts...>;

// HE_DISPATCH is used to generate lambda expressions that are similar but
// of different types.
#define HE_DISPATCH(...) \
  Overloaded { HE_FOR_EACH(__VA_ARGS__), }

}  // namespace heu::lib::phe
