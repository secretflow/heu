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

#include "heu/library/algorithms/mock/mock.h"
#include "heu/library/algorithms/paillier_float/paillier.h"
#include "heu/library/algorithms/paillier_zahlen/paillier.h"

namespace heu::lib::phe {

// If you add a new schema, change this !!
enum class SchemaType {
  None,  // Mock He
  ZPaillier,
  FPaillier,
};

// SchemaType <-> String
// If you add a new schema, change schema <-> string map in schema.cc !!
std::vector<SchemaType> GetAllSchema();
SchemaType ParseSchemaType(const std::string& schema_string);
std::string SchemaToString(SchemaType schema_type);

// If you add a new schema, change this !!
// SchemaType is in the same order as HE_FOR_EACH
// clang-format off
#define HE_FOR_EACH(invoke, ...)                             \
  invoke(::heu::lib::algorithms::mock, ##__VA_ARGS__),       \
  invoke(::heu::lib::algorithms::paillier_z, ##__VA_ARGS__), \
invoke(::heu::lib::algorithms::paillier_f, ##__VA_ARGS__)
// clang-format on

#define HE_COMBINE_NS_TYPE(ns, type) ns::type
#define HE_NAMESPACE_LIST(type) HE_FOR_EACH(HE_COMBINE_NS_TYPE, type)

}  // namespace heu::lib::phe
