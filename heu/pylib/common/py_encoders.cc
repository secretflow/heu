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

#include "heu/pylib/common/py_encoders.h"

namespace heu::pylib {

std::string PyIntegerEncoder::ToString() const {
  return fmt::format("IntegerEncoder(scale={})", encoder_.GetScale());
}

std::string PyFloatEncoder::ToString() const {
  return fmt::format("FloatEncoder(scale={})", encoder_.GetScale());
}

std::string PyBigintEncoder::ToString() const {
  return fmt::format("BigintEncoder()");
}

std::string PyBatchEncoder::ToString() const { return encoder_.ToString(); }

}  // namespace heu::pylib
