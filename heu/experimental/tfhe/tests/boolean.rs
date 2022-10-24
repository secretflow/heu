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

extern crate concrete_boolean;

#[test]
fn test_boolean() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = concrete_boolean::gen_keys();

    // We use the client secret key to encrypt two messages:
    let ct_1 = client_key.encrypt(true);
    let ct_2 = client_key.encrypt(false);

    // We use the server public key to execute a boolean circuit:
    // if ((NOT ct_2) NAND (ct_1 AND ct_2)) then (NOT ct_2) else (ct_1 AND ct_2)
    let ct_3 = server_key.not(&ct_2);
    let ct_4 = server_key.and(&ct_1, &ct_2);
    let ct_5 = server_key.nand(&ct_3, &ct_4);
    let ct_6 = server_key.mux(&ct_5, &ct_3, &ct_4);

    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_6);
    assert_eq!(output, true);
}
