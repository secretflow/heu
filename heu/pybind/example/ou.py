#  Copyright 2022 Ant Group Co., Ltd.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from heu import ou

pk, sk = ou.keygen(1024)
print(pk)
print(sk)

encrypt = ou.Encryptor(pk)
decrypt = ou.Decryptor(pk, sk)
evaluator = ou.Evaluator(pk)

ct1 = encrypt.encrypt_raw(123)
ct2 = encrypt.encrypt_raw(456)
ct3 = evaluator.add(ct1, ct2)
print(decrypt.decrypt_raw(ct3))  # 579

# batch encoding

bc = ou.BatchEncoder()
pt1 = bc.encode(123, 456)
pt2 = bc.encode(789, 101112)

ct1 = encrypt.encrypt(pt1)
ct2 = encrypt.encrypt(pt2)
ct3 = evaluator.add(ct1, ct2)

pt3 = decrypt.decrypt(ct3)
print(bc.decode(pt3))  # (912, 101568)
