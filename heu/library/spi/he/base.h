// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/utils/spi/argument/arg_set.h"
#include "yacl/utils/spi/item.h"

namespace heu::lib::spi {

/*
 * Item 本质上在 C++ 之上构建了一套无类型系统，类似于
 * Python，任何类型都可以转换成 Item， 反之 Item 也可以变成任何实际类型。
 *
 * 一些缩写约定：
 *   PT => Plaintext
 *   CT => Ciphertext
 *   PTs => Plaintext Array
 *   CTs => Ciphertext Array
 */
using Item = yacl::Item;

using SpiArgs = yacl::SpiArgs;

}  // namespace heu::lib::spi
