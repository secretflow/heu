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

#include <type_traits>

namespace heu::lib::phe {

#define FOR_EACH_TYPE(var)                                                    \
  if constexpr (std::is_same_v<                                               \
                    std::remove_cv_t<std::remove_reference_t<decltype(var)>>, \
                    std::monostate>) {                                        \
    YASL_THROW("variable uninitialized (no schema info)");                    \
  } else

// functions with 1 args //

#define HE_METHOD_VOID_1(ns, clazz, func, type1, out1) \
  [&](const ns::clazz& eval) { eval.func(&out1->As<ns::type1>()); }

#define HE_METHOD_RET_1(ns, clazz, ret, func, type1, in1) \
  [&](const ns::clazz& eval) -> ret {                     \
    return ret(eval.func(in1.As<ns::type1>()));           \
  }

// functions with 2 args //

#define HE_METHOD_VOID_2(ns, clazz, func, type1, out1, type2, in2) \
  [&](const ns::clazz& eval) {                                     \
    eval.func(&out1->As<ns::type1>(), in2.As<ns::type2>());        \
  }

#define HE_METHOD_RET_2(ns, clazz, ret, func, type1, in1, type2, in2) \
  [&](const ns::clazz& eval) -> ret {                                 \
    return ret(eval.func(in1.As<ns::type1>(), in2.As<ns::type2>()));  \
  }

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

#define HE_DISPATCH_RET(T, ...)                        \
  Overloaded {                                         \
    [](const std::monostate&) -> T {                   \
      YASL_THROW("illegal variable (no schema info)"); \
    },                                                 \
        HE_FOR_EACH(__VA_ARGS__),                      \
  }

#define HE_DISPATCH(...) HE_DISPATCH_RET(void, ##__VA_ARGS__)

}  // namespace heu::lib::phe
