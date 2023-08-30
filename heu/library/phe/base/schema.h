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

#include "msgpack.hpp"

#include "heu/library/algorithms/dgk/dgk.h"
#include "heu/library/algorithms/elgamal/elgamal.h"
#include "heu/library/algorithms/mock/mock.h"
#include "heu/library/algorithms/ou/ou.h"
#include "heu/library/algorithms/paillier_clustar_fpga/clustar_fpga.h"
#include "heu/library/algorithms/paillier_float/paillier.h"
#include "heu/library/algorithms/paillier_ipcl/ipcl.h"
#include "heu/library/algorithms/paillier_zahlen/paillier.h"

// [SPI: Please register your algorithm here] || progress: (1 of 5)
// Do not forget to add your algo header file here
// #include "heu/library/algorithms/your_algo/algo.h"

namespace heu::lib::phe {

#define ECHO_true(str) str,
#define ECHO_false(str)
#define ENUM_ELEMENT_HELPER(enable, name) ECHO_##enable(name)
#define ENUM_ELEMENT(enable, name) ENUM_ELEMENT_HELPER(enable, name)

// [SPI: Please register your algorithm here] || progress: (2 of 5)
// If you add a new schema, change this !!
// clang-format off
enum class SchemaType {
  ENUM_ELEMENT(true, Mock)  // Mock He
  ENUM_ELEMENT(true, OU)
  ENUM_ELEMENT(ENABLE_IPCL, IPCL)
  ENUM_ELEMENT(true, ZPaillier)  // Preferred
  ENUM_ELEMENT(true, FPaillier)
  ENUM_ELEMENT(ENABLE_CLUSTAR_FPGA, ClustarFPGA)
  ENUM_ELEMENT(true, ElGamal)
  ENUM_ELEMENT(true, DGK)
  // YOUR_ALGO
};
// clang-format on

// SchemaType <-> String
// If you add a new schema, change schema <-> string map in schema.cc !!
std::vector<SchemaType> GetAllSchema();
SchemaType ParseSchemaType(const std::string& schema_string);
// Select schemas with pattern 'regex_pattern'
// full_match: true - The whole schema string must match pattern
//             false - Any substring matching pattern will be selected
std::vector<SchemaType> SelectSchemas(const std::string& regex_pattern,
                                      bool full_match = true);
std::string SchemaToString(SchemaType schema_type);
std::vector<std::string> GetSchemaAliases(SchemaType schema_type);
std::ostream& operator<<(std::ostream& os, SchemaType st);
// for fmt lib
std::string format_as(SchemaType i);

// Below are some helper macros
#define INVOKE_true(func_or_macro, schema_ns, ...) \
  , func_or_macro(schema_ns, ##__VA_ARGS__)
#define INVOKE_false(func_or_macro, schema_ns, ...)

#define INVOKE_HELPER(enable, func_or_macro, schema_ns, ...) \
  INVOKE_##enable(func_or_macro, schema_ns, ##__VA_ARGS__)

#define INVOKE(enable, func_or_macro, schema_ns, ...) \
  INVOKE_HELPER(enable, func_or_macro, schema_ns, ##__VA_ARGS__)

// [SPI: Please register your algorithm here] || progress: (3 of 5)
// If you add a new schema, change this !!
// HE_FOR_EACH must be in the same order as SchemaType
// clang-format off
#define HE_FOR_EACH(func_or_macro, ...)                             \
  func_or_macro(::heu::lib::algorithms::mock, ##__VA_ARGS__)        \
  INVOKE(true, func_or_macro, ::heu::lib::algorithms::ou, ##__VA_ARGS__)                   \
  INVOKE(ENABLE_IPCL, func_or_macro, ::heu::lib::algorithms::paillier_ipcl, ##__VA_ARGS__) \
  INVOKE(true, func_or_macro, ::heu::lib::algorithms::paillier_z, ##__VA_ARGS__)           \
  INVOKE(true, func_or_macro, ::heu::lib::algorithms::paillier_f, ##__VA_ARGS__)           \
  INVOKE(ENABLE_CLUSTAR_FPGA, func_or_macro, ::heu::lib::algorithms::paillier_clustar_fpga, ##__VA_ARGS__) \
  INVOKE(true, func_or_macro, ::heu::lib::algorithms::elgamal, ##__VA_ARGS__) \
  INVOKE(true, func_or_macro, ::heu::lib::algorithms::dgk, ##__VA_ARGS__)

// [SPI: Please register your algorithm here] || progress: (4 of 5)
// If you add a new schema, change this !!
// If the Plaintext class is reused with other algorithms, there is no need to
// repeat the registration here. For example, paillier_z and paillier_f both use
// MPInt to store plaintext, so MPInt only appears once.
#define PLAINTEXT_FOR_EACH(func_or_macro, ...)                                   \
  func_or_macro(::heu::lib::algorithms, MPInt, ##__VA_ARGS__)                    \
  INVOKE(true, func_or_macro, ::heu::lib::algorithms::mock, Plaintext, ##__VA_ARGS__)                 \
  INVOKE(ENABLE_IPCL, func_or_macro, ::heu::lib::algorithms::paillier_ipcl, Plaintext, ##__VA_ARGS__) \
  INVOKE(ENABLE_CLUSTAR_FPGA, func_or_macro, ::heu::lib::algorithms::paillier_clustar_fpga, Plaintext, ##__VA_ARGS__) \
  // INVOKE(true, func_or_macro, ::heu::lib::algorithms::your_algo, Plaintext, ##__VA_ARGS__)
// clang-format on

#define HE_COMBINE_NS_TYPE(ns, type) ns::type
#define HE_NAMESPACE_LIST(type) HE_FOR_EACH(HE_COMBINE_NS_TYPE, type)

#define HE_PLAINTEXT_TYPES PLAINTEXT_FOR_EACH(HE_COMBINE_NS_TYPE)

}  // namespace heu::lib::phe

MSGPACK_ADD_ENUM(heu::lib::phe::SchemaType);
