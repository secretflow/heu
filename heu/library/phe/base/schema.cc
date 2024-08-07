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

#include "heu/library/phe/base/schema.h"

#include <regex>

#include "absl/strings/ascii.h"

namespace heu::lib::phe {

#define MAP_ITEM_true(enum_item, ...)                    \
  {                                                      \
    SchemaType::enum_item, { #enum_item, ##__VA_ARGS__ } \
  }
#define MAP_ITEM_false(...) \
  {}
#define MAP_ITEM_HELPER(enable, enum_item, ...) \
  MAP_ITEM_##enable(enum_item, ##__VA_ARGS__)
#define MAP_ITEM(enable, enum_item, ...) \
  MAP_ITEM_HELPER(enable, enum_item, ##__VA_ARGS__)

// [SPI: Please register your algorithm here] || progress: (5 of 5)
// Please add aliases to your algorithm, note that aliases should not be
// duplicated with other algorithms.
// Aliases are case-sensitive.
// 请给您的算法添加别名，别名区分大小写，注意别名必须唯一，不与其它算法重复
static const std::map<SchemaType, std::vector<std::string>,
                      std::less<SchemaType>>
    kSchemaTypeToString = {
        MAP_ITEM(true, Mock, "none", "mock", "plain"),
        MAP_ITEM(true, OU, "ou", "okamoto-uchiyama"),
        MAP_ITEM(ENABLE_IPCL, IPCL, "ipcl", "ipcl-paillier", "ipcl_paillier",
                 "paillier_ipcl", "paillier-ipcl"),
        MAP_ITEM(true, ZPaillier, "z-paillier", "zpaillier", "paillier",
                 "paillier_z", "paillier_zahlen"),
        MAP_ITEM(true, FPaillier, "f-paillier", "fpaillier", "paillier_f",
                 "paillier_float"),
        MAP_ITEM(true, IcPaillier, "ic-paillier", "icpaillier", "ic_paillier",
                 "paillier_ic", "paillier-interconnection"),
        MAP_ITEM(ENABLE_GPAILLIER, GPaillier, "g-paillier", "gpaillier",
                 "paillier_g", "paillier_gpu"),
        MAP_ITEM(ENABLE_CLUSTAR_FPGA, ClustarFPGA, "clustarfpga",
                 "clustarfpga-paillier", "clustarfpga_paillier",
                 "paillier_clustarfpga", "paillier-clustarfpga"),
        MAP_ITEM(true, ElGamal, "elgamal", "ec_elgamal", "exponential_elgamal",
                 "exp_elgamal", "lifted_elgamal"),
        MAP_ITEM(true, DGK, "dgk", "damgard-geisler-kroigaard",
                 "damgard_geisler_kroigaard"),
        MAP_ITEM(true, DJ, "dj", "damgard-jurik", "damgard_jurik"),
        // MAP_ITEM(ENABLE, YOUR_ALGO, "one_or_more_name_alias"),
};

std::vector<SchemaType> GetAllSchema() {
  const static std::vector<SchemaType> res = []() {
    std::vector<SchemaType> tmp;
    for (const auto &item : kSchemaTypeToString) {
      tmp.push_back(item.first);
    }
    return tmp;
  }();
  return res;
}

SchemaType ParseSchemaType(const std::string &schema_string) {
  auto schema_str = absl::AsciiStrToLower(schema_string);
  for (const auto &schema : kSchemaTypeToString) {
    for (const auto &alias : schema.second) {
      if (alias == schema_str) {
        return schema.first;
      }
    }
  }
  YACL_THROW("Unknown schema type {}", schema_string);
}

std::vector<SchemaType> SelectSchemas(const std::string &regex_pattern,
                                      bool full_match) {
  std::vector<SchemaType> res;
  std::regex p(regex_pattern);
  for (const auto &schema : kSchemaTypeToString) {
    for (const auto &alias : schema.second) {
      if (full_match ? std::regex_match(alias, p)
                     : std::regex_search(alias, p)) {
        res.push_back(schema.first);
        break;
      }
    }
  }
  return res;
}

std::string SchemaToString(SchemaType schema_type) {
  return kSchemaTypeToString.at(schema_type)[0];
}

std::vector<std::string> GetSchemaAliases(SchemaType schema_type) {
  return kSchemaTypeToString.at(schema_type);
}

std::ostream &operator<<(std::ostream &os, SchemaType st) {
  return os << SchemaToString(st);
}

SchemaType NamespaceIdx2Schema(uint8_t ns_idx) {
  const static auto schema_list = GetAllSchema();
  YACL_ENFORCE(ns_idx < schema_list.size(), "ns_idx overflow: {}, total {}",
               ns_idx, schema_list.size());
  return schema_list[ns_idx];
}

uint8_t Schema2NamespaceIdx(SchemaType schema) {
  static auto schema_map = []() {
    auto schema_list = GetAllSchema();
    std::unordered_map<SchemaType, uint8_t> tmp;
    for (uint8_t i = 0; i < schema_list.size(); ++i) {
      tmp.insert({schema_list[i], i});
    }
    return tmp;
  }();
  YACL_ENFORCE(schema_map.count(schema) > 0,
               "Schema {} not enabled or not supported.", schema);
  return schema_map.at(schema);
}

std::string format_as(SchemaType i) { return SchemaToString(i); }

}  // namespace heu::lib::phe
