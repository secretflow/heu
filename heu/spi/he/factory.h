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

#pragma once

#include <functional>

#include "heu/spi/he/he_kit.h"

namespace heu::spi {

using HeSpiCreatorT =
    std::function<std::unique_ptr<HeKit>(Schema, const SpiArgs &)>;

// Given config, return whether feature is supported by this lib.
// Returns: True is supported and false is unsupported.
using HeSpiCheckerT = std::function<bool(Schema, const SpiArgs &)>;

class HeFactory final : private yacl::SpiFactoryBase<HeKit> {
 public:
  using Super = yacl::SpiFactoryBase<HeKit>;

  static HeFactory &Instance();

  // Create a library instance
  //
  // If `extra_args` explicitly specifies the library to be created (with
  // ArgLib=xxx_name), the HeFactory checks if the library supports the input
  // parameters; if it does, it creates an instance of the library.
  // If `extra_args` does not specify a library name, the HeFactory
  // automatically selects the highest-performing library that meets the
  // parameter requirements and creates an instance.
  //
  // 中文(translation)：
  // 如果extra_args明确指定了要创建的库，则工厂检查该库是否支持输入参数，如果支持则创建库实例。
  // 如果extra_args未指定库名称，则工厂自动选择性能最高，且满足参数要求的库并创建实例
  template <typename... T>
  std::unique_ptr<HeKit> Create(Schema schema, T &&...extra_args) const {
    return Super::Create(Schema2String(schema), std::forward<T>(extra_args)...);
  }

  std::unique_ptr<HeKit> CreateFromArgPkg(Schema schema,
                                          const SpiArgs &args) const {
    return Super::CreateFromArgPkg(Schema2String(schema), args);
  }

  // List all registered libraries
  std::vector<std::string> ListLibraries() const;

  // List libraries that support this schema and args
  //
  // * If `extra_args` explicitly specifies the library to create (for example,
  // ArgLib=xxx_name), then the method will check if the library supports the
  // specified parameters. If it does, it returns a list containing only that
  // library; otherwise, it returns an empty list.
  // * If `extra_args` does not specify a library name, then the method returns
  // the names of all libraries that satisfy the parameter requirements.
  template <typename... T>
  std::vector<std::string> ListLibraries(Schema schema,
                                         T &&...extra_args) const {
    return Super::ListLibraries(Schema2String(schema),
                                std::forward<T>(extra_args)...);
  }

  std::vector<std::string> ListLibrariesFromArgPkg(Schema schema,
                                                   const SpiArgs &args) const {
    return Super ::ListLibrariesFromArgPkg(Schema2String(schema), args);
  }

  void Register(const std::string &lib_name, int64_t performance,
                const HeSpiCheckerT &checker, const HeSpiCreatorT &creator);
};

/*
 * The sign of creator/checker:
 * > std::unique_ptr<HeKit> Create(const std::string &schema, const SpiArgs &);
 * > bool Check(const std::string &schema, const SpiArgs &args);
 */
#define REGISTER_HE_LIBRARY(lib_name, performance, checker, creator)        \
  REGISTER_SPI_LIBRARY_HELPER(::heu::spi::HeFactory, lib_name, performance, \
                              checker, creator)

}  // namespace heu::spi
