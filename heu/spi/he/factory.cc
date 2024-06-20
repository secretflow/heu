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

#include "heu/spi/he/factory.h"

namespace heu::spi {

HeFactory &HeFactory::Instance() {
  static HeFactory factory;
  return factory;
}

std::vector<std::string> HeFactory::ListLibraries() const {
  // we do not want to export other ListLibraries functions,
  // so we do not use "using Super::ListLibraries;"
  return Super::ListLibraries();
}

void HeFactory::Register(const std::string &lib_name, int64_t performance,
                         const HeSpiCheckerT &checker,
                         const HeSpiCreatorT &creator) {
  Super ::Register(
      lib_name, performance,
      [checker](const std::string &schema, const SpiArgs &args) {
        return checker(String2Schema(schema), args);
      },
      [creator](const std::string &schema, const SpiArgs &args) {
        return creator(String2Schema(schema), args);
      });
}

}  // namespace heu::spi
