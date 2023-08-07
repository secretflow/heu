// Copyright 2023 Clustar Technology Co., Ltd.
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

#include "heu/library/algorithms/util/he_object.h"
#include "heu/library/algorithms/util/mp_int.h"
#include "heu/library/algorithms/paillier_clustar_fpga/public_key.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

class CSecrKeyHelper;
class SecretKey : public HeObject<SecretKey> {
public:
    SecretKey() = default;
    explicit SecretKey(const PublicKey& pub_key, const MPInt& p, const MPInt& q);

    bool operator==(const SecretKey &other) const;
    bool operator!=(const SecretKey &other) const;

    std::string ToString() const override;

    // Serialize and Deserialize
    MSGPACK_DEFINE(p_, q_, p_square_, q_square_, q_inverse_, hp_, hq_, pub_key_);

    // Functions for unit test
    const MPInt& GetP() const;
    const MPInt& GetQ() const;
    const MPInt& GetPSquare() const;
    const MPInt& GetQSquare() const;
    const MPInt& GetQInverse() const;
    const MPInt& GetHP() const;
    const MPInt& GetHQ() const;
    const PublicKey& GetPubKey() const;

private:
    void HFunc(const MPInt& x, const MPInt& x_square, MPInt& result);

    friend class CSecrKeyHelper;

private:
    MPInt p_;
    MPInt q_;
    MPInt p_square_;
    MPInt q_square_;
    MPInt q_inverse_;
    MPInt hp_;
    MPInt hq_;
    PublicKey pub_key_;
};

} // heu::lib::algorithms::paillier_clustar_fpga
