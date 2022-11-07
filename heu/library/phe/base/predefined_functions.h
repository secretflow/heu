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

#include <experimental/type_traits>

#include "absl/types/span.h"

namespace heu::lib::phe {

// invoke functions with 0 args //

#define DEFINE_INVOKE_METHOD_RET_0(ret, func)                                \
  template <typename CLAZZ>                                                  \
  using kHasScalar##func = decltype(std::declval<const CLAZZ&>().func());    \
                                                                             \
  /* Call scalar SPI */                                                      \
  template <typename CLAZZ>                                                  \
  auto DoCall##func(const CLAZZ& sub_clazz)                                  \
      ->std::enable_if_t<                                                    \
          std::experimental::is_detected_v<kHasScalar##func, CLAZZ>, ret> {  \
    return ret(sub_clazz.func());                                            \
  }                                                                          \
                                                                             \
  /* Call vectorized SPI */                                                  \
  template <typename CLAZZ>                                                  \
  auto DoCall##func(const CLAZZ& sub_clazz)                                  \
      ->std::enable_if_t<                                                    \
          !std::experimental::is_detected_v<kHasScalar##func, CLAZZ>, ret> { \
    return ret(sub_clazz.func(1)[0]);                                        \
  }

// invoke functions with 1 args (with return value) //

#define DEFINE_INVOKE_METHOD_RET_1(ret, func)                                \
  template <typename CLAZZ, typename TYPE1>                                  \
  using kHasScalar##func =                                                   \
      decltype(std::declval<const CLAZZ&>().func(TYPE1()));                  \
                                                                             \
  /* Call scalar SPI */                                                      \
  template <typename CLAZZ, typename TYPE1>                                  \
  auto DoCall##func(const CLAZZ& sub_clazz, const TYPE1& in1)                \
      ->std::enable_if_t<                                                    \
          std::experimental::is_detected_v<kHasScalar##func, CLAZZ, TYPE1>,  \
          ret> {                                                             \
    return ret(sub_clazz.func(in1));                                         \
  }                                                                          \
                                                                             \
  /* Call vectorized SPI */                                                  \
  template <typename CLAZZ, typename TYPE1>                                  \
  auto DoCall##func(const CLAZZ& sub_clazz, const TYPE1& in1)                \
      ->std::enable_if_t<                                                    \
          !std::experimental::is_detected_v<kHasScalar##func, CLAZZ, TYPE1>, \
          ret> {                                                             \
    return ret(sub_clazz.func(absl::MakeConstSpan<>({&in1}))[0]);            \
  }

#define DO_INVOKE_METHOD_RET_1(ns, clazz, func, type1, in1) \
  [&](const ns::clazz& eval) {                              \
    return DoCall##func(eval, (in1).As<ns::type1>());       \
  }

// invoke functions with 1 args (no return value) //

#define DEFINE_INVOKE_METHOD_VOID_1(func)                                      \
  template <typename CLAZZ, typename TYPE1>                                    \
  using kHasScalar##func =                                                     \
      decltype(std::declval<const CLAZZ&>().func(std::declval<TYPE1*>()));     \
                                                                               \
  /* Call scalar SPI */                                                        \
  template <typename CLAZZ, typename TYPE1>                                    \
  auto DoCall##func(const CLAZZ& sub_clazz, TYPE1* out1)                       \
      ->std::enable_if_t<                                                      \
          std::experimental::is_detected_v<kHasScalar##func, CLAZZ, TYPE1>> {  \
    (sub_clazz.func(out1));                                                    \
  }                                                                            \
                                                                               \
  /* Call vectorized SPI */                                                    \
  template <typename CLAZZ, typename TYPE1>                                    \
  auto DoCall##func(const CLAZZ& sub_clazz, TYPE1* out1)                       \
      ->std::enable_if_t<                                                      \
          !std::experimental::is_detected_v<kHasScalar##func, CLAZZ, TYPE1>> { \
    TYPE1* wrap[] = {out1};                                                    \
    (sub_clazz.func(absl::MakeSpan<>(wrap)));                                  \
  }

#define DO_INVOKE_METHOD_VOID_1(ns, clazz, func, type1, out1) \
  [&](const ns::clazz& eval) { DoCall##func(eval, &((out1)->As<ns::type1>())); }

// invoke functions with 2 args (with return value) //

#define DEFINE_INVOKE_METHOD_RET_2(ret, func)                        \
  template <typename CLAZZ, typename TYPE1, typename TYPE2>          \
  using kHasScalar##func =                                           \
      decltype(std::declval<const CLAZZ&>().func(TYPE1(), TYPE2())); \
                                                                     \
  /* Call scalar SPI */                                              \
  template <typename CLAZZ, typename TYPE1, typename TYPE2>          \
  auto DoCall##func(const CLAZZ& sub_clazz, const TYPE1& in1,        \
                    const TYPE2& in2)                                \
      ->std::enable_if_t<std::experimental::is_detected_v<           \
                             kHasScalar##func, CLAZZ, TYPE1, TYPE2>, \
                         ret> {                                      \
    return ret(sub_clazz.func(in1, in2));                            \
  }                                                                  \
                                                                     \
  /* Call vectorized SPI */                                          \
  template <typename CLAZZ, typename TYPE1, typename TYPE2>          \
  auto DoCall##func(const CLAZZ& sub_clazz, const TYPE1& in1,        \
                    const TYPE2& in2)                                \
      ->std::enable_if_t<!std::experimental::is_detected_v<          \
                             kHasScalar##func, CLAZZ, TYPE1, TYPE2>, \
                         ret> {                                      \
    return ret(sub_clazz.func(absl::MakeConstSpan<>({&in1}),         \
                              absl::MakeConstSpan<>({&in2}))[0]);    \
  }

#define DO_INVOKE_METHOD_RET_2(ns, clazz, func, type1, in1, type2, in2)      \
  [&](const ns::clazz& eval) {                                               \
    return DoCall##func(eval, (in1).As<ns::type1>(), (in2).As<ns::type2>()); \
  }

// invoke functions with 2 args (no return value) //

#define DEFINE_INVOKE_METHOD_VOID_2(func)                                     \
  template <typename CLAZZ, typename TYPE1, typename TYPE2>                   \
  using kHasScalar##func = decltype(std::declval<const CLAZZ&>().func(        \
      std::declval<TYPE1*>(), TYPE2()));                                      \
                                                                              \
  /* Call scalar SPI */                                                       \
  template <typename CLAZZ, typename TYPE1, typename TYPE2>                   \
  auto DoCall##func(const CLAZZ& sub_clazz, TYPE1* in_out1, const TYPE2& in2) \
      ->std::enable_if_t<std::experimental::is_detected_v<                    \
          kHasScalar##func, CLAZZ, TYPE1, TYPE2>> {                           \
    (sub_clazz.func(in_out1, in2));                                           \
  }                                                                           \
                                                                              \
  /* Call vectorized SPI */                                                   \
  template <typename CLAZZ, typename TYPE1, typename TYPE2>                   \
  auto DoCall##func(const CLAZZ& sub_clazz, TYPE1* in_out1, const TYPE2& in2) \
      ->std::enable_if_t<!std::experimental::is_detected_v<                   \
          kHasScalar##func, CLAZZ, TYPE1, TYPE2>> {                           \
    TYPE1* wrap[] = {in_out1};                                                \
    (sub_clazz.func(absl::MakeSpan<>(wrap), absl::MakeConstSpan<>({&in2})));  \
  }

#define DO_INVOKE_METHOD_VOID_2(ns, clazz, func, type1, in_out1, type2, in2)  \
  [&](const ns::clazz& eval) {                                                \
    DoCall##func(eval, &((in_out1)->As<ns::type1>()), (in2).As<ns::type2>()); \
  }

}  // namespace heu::lib::phe
