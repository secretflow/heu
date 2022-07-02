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

#include "heu/library/phe/schema.h"

#include "absl/strings/ascii.h"

namespace heu::lib::phe {

static std::map<SchemaType, std::vector<std::string>> kSchemaTypeToString = {
    {SchemaType::None, {"none", "mock", "plain"}},
    {SchemaType::ZPaillier,
     {"z-paillier", "zpaillier", "paillier", "paillier_z", "paillier_zahlen"}},
    {SchemaType::FPaillier,
     {"f-paillier", "fpaillier", "paillier_f", "paillier_float"}},
};

std::vector<SchemaType> GetAllSchema() {
  std::vector<SchemaType> res;
  res.reserve(kSchemaTypeToString.size());
  for (const auto& item : kSchemaTypeToString) {
    res.push_back(item.first);
  }
  return res;
}

SchemaType ParseSchemaType(const std::string& schema_string) {
  auto schema_str = absl::AsciiStrToLower(schema_string);
  for (const auto& schema : kSchemaTypeToString) {
    for (const auto& alias : schema.second) {
      if (alias == schema_str) {
        return schema.first;
      }
    }
  }
  YASL_THROW("Unknown schema type {}", schema_string);
}

std::string SchemaToString(SchemaType schema_type) {
  return kSchemaTypeToString[schema_type][0];
}

}  // namespace heu::lib::phe
