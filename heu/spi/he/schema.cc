// Copyright 2024 Ant Group Co., Ltd.
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

#include "heu/spi/he/schema.h"

#include <map>
#include <string>

#include "yacl/base/exception.h"

namespace heu::spi {

const std::set<Schema> &ListAllSchema() {
  static const std::set<Schema> all_schema = []() {
    std::set<Schema> res;
    for (const auto &s : kSchema2String) {
      res.insert(s.first);
    }
    return res;
  }();

  return all_schema;
}

std::string Schema2String(Schema schema) { return kSchema2String.at(schema); }

Schema String2Schema(std::string_view name) {
  const std::map<std::string_view, Schema> str2schema = []() {
    std::map<std::string_view, Schema> res;
    for (const auto &s : kSchema2String) {
      YACL_ENFORCE(res.insert({s.second, s.first}).second,
                   "duplicate schema name {}", s.second);
    }
    return res;
  }();

  auto it = str2schema.find(name);
  if (it == str2schema.end()) {
    return Schema::Unknown;
  }
  return it->second;
}

}  // namespace heu::spi
