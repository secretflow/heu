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

#include "heu/spi/auto_test/tool.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "heu/spi/he/factory.h"

namespace heu::spi::test {

auto SelectHeKitsForTest(std::unordered_set<FeatureSet> groups)
    -> decltype(::testing::ValuesIn(std::vector<std::shared_ptr<HeKit>>())) {
  // map: schema -> config
  static std::multimap<Schema, SpiArgs> kSpecialConfigs = {
      {Schema::MockBfv,
       {ArgPolyModulusDegree = 2048, ArgGenNewPkSk = true, ArgGenNewRlk = true,
        ArgGenNewGlk = true, ArgGenNewBsk = true}},
      {Schema::MockCkks,
       {ArgPolyModulusDegree = 4096, ArgGenNewPkSk = true, ArgGenNewRlk = true,
        ArgGenNewGlk = true, ArgScale = 100}},
  };

  const static std::set<std::shared_ptr<HeKit>> all_kits = []() {
    // below code only runs once
    std::set<std::shared_ptr<HeKit>> res;
    for (const auto &schema : ListAllSchema()) {
      if (kSpecialConfigs.count(schema) > 0) {
        // use special configs
        for (auto pos = kSpecialConfigs.equal_range(schema);
             pos.first != pos.second; ++pos.first) {
          SpiArgs args = pos.first->second;
          for (const auto &lib : HeFactory::Instance().ListLibrariesFromArgPkg(
                   schema, pos.first->second)) {
            args.Insert(ArgLib = lib);
            SPDLOG_INFO("Create HeKit({}, args={})", schema, args);
            res.insert(HeFactory::Instance().CreateFromArgPkg(schema, args));
          }
        }
      } else {
        // use default config
        for (const auto &lib : HeFactory::Instance().ListLibraries(schema)) {
          SPDLOG_INFO("Create HeKit(schema={}, lib={})", schema, lib);
          res.insert(HeFactory::Instance().Create(schema, ArgLib = lib,
                                                  ArgGenNewPkSk = true));
        }
      }
    }
    return res;
  }();

  std::vector<std::shared_ptr<HeKit>> res;
  for (const auto &kit : all_kits) {
    if (groups.count(kit->GetFeatureSet()) > 0) {
      res.push_back(kit);
    }
  }
  return ::testing::ValuesIn(res);
}

std::string GenTestName(const std::shared_ptr<HeKit> &kit) {
  static std::map<std::pair<Schema, std::string>, int64_t> counter;

  // google test name must be alnum or '_'
  auto key = std::make_pair(kit->GetSchema(), kit->GetLibraryName());
  auto name =
      fmt::format("{}_from_{}_{}", key.first, key.second, counter[key]++);
  std::replace_if(
      name.begin(), name.end(), [](char c) { return !std::isalnum(c); }, '_');
  return name;
}

}  // namespace heu::spi::test
