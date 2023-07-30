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

#include "heu/library/algorithms/leichi_paillier/ciphertext.h"
#include <string_view>

namespace heu::lib::algorithms::leichi_paillier {

    std::string Ciphertext::ToString() const {
        char* str = BN_bn2dec(bn_);
        std::string result(str);
        return result;
    }

    std::ostream &operator<<(std::ostream &os, const Ciphertext &ct) {
        char* str = BN_bn2dec(ct.bn_);
        os << str;
        return os;
    }

    bool Ciphertext::operator==(const Ciphertext &other) const {
    return (BN_cmp(bn_, other.bn_) == 0)?true:false;
    }

    bool Ciphertext::operator!=(const Ciphertext &other) const {
    return (BN_cmp(bn_, other.bn_) == 0)?true:false;
    }

}  // namespace heu::lib::algorithms::leichi_paillier
