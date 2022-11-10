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

import unittest
import random
from heu import phe


class BasicCase(unittest.TestCase):
    def setUp(self) -> None:
        self.ctx = phe.setup(phe.SchemaType.ZPaillier, 2048)
        self.encryptor = self.ctx.encryptor()
        self.decryptor = self.ctx.decryptor()
        self.evaluator = self.ctx.evaluator()

    def test_schema(self):
        self.assertEqual(phe.SchemaType.ZPaillier, phe.parse_schema_type("z-paillier"))
        self.assertEqual(phe.SchemaType.ZPaillier, phe.parse_schema_type("paillier"))
        self.assertEqual(phe.SchemaType.Mock, phe.parse_schema_type("plain"))
        self.assertEqual(phe.SchemaType.Mock, phe.parse_schema_type("none"))
        self.assertEqual(phe.SchemaType.Mock, phe.parse_schema_type("mock"))

    def test_plaintext(self):
        case = [
            0,
            1,
            -1,
            2,
            -2,
            -2147483648,
            -2147483649,
            2147483647,
            2147483648,
            -9223372036854775807,
            -9223372036854775808,
            -9223372036854775809,
            9223372036854775806,
            9223372036854775807,
            9223372036854775808,
            18446744073709551615,
            18446744073709551616,
            -170141183460469231731687303715884105728,
            170141183460469231731687303715884105727,
        ]
        for c in case:
            pt = phe.Plaintext(self.ctx.get_schema(), c)
            self.assertEqual(str(pt), str(c))
            self.assertEqual(int(pt), c)
            pt *= phe.Plaintext(self.ctx.get_schema(), 123456)
            self.assertEqual(int(pt), c * 123456)

        # to_bytes
        max_bytes = 16
        for c in case:
            self.assertEqual(
                phe.Plaintext(self.ctx.get_schema(), c).to_bytes(max_bytes, "big"),
                c.to_bytes(max_bytes, "big", signed=True),
            )
            self.assertEqual(
                phe.Plaintext(self.ctx.get_schema(), c).to_bytes(
                    max_bytes, "little"
                ),
                c.to_bytes(max_bytes, "little", signed=True),
            )

        # below are big number cases
        case = [random.getrandbits(2 ** i) for i in range(4, 14) for _ in range(100)]
        for c in case:
            pt = phe.Plaintext(self.ctx.get_schema(), c)
            self.assertEqual(str(pt), str(c))
            self.assertEqual(int(pt), c)
            self.assertTrue(pt == pt)
            self.assertTrue(pt <= pt)
            self.assertTrue(pt >= pt)
            pt *= phe.Plaintext(self.ctx.get_schema(), 123456789)
            self.assertEqual(int(pt), c * 123456789)

        for c in case:
            pt = phe.Plaintext(self.ctx.get_schema(), -c)
            self.assertEqual(str(pt), "-" + str(c))
            self.assertEqual(int(pt), -c)
            self.assertTrue(pt == pt)
            self.assertTrue(pt <= pt)
            self.assertTrue(pt >= pt)
            self.assertTrue(pt < phe.Plaintext(self.ctx.get_schema(), 0))

        max_bytes = 2 ** 14 // 8
        for c in case:
            self.assertEqual(
                phe.Plaintext(self.ctx.get_schema(), c).to_bytes(max_bytes, "big"),
                c.to_bytes(max_bytes, "big", signed=True),
                f"c is {c}",
            )
            self.assertEqual(
                phe.Plaintext(self.ctx.get_schema(), c).to_bytes(
                    max_bytes, "little"
                ),
                c.to_bytes(max_bytes, "little", signed=True),
                f"c is {c}",
            )

    def test_enc_dec(self):
        ct1 = self.encryptor.encrypt_raw(123)
        ct2 = self.encryptor.encrypt_raw(456)

        self.assertEqual(
            self.decryptor.decrypt_raw(self.evaluator.add(ct1, ct2)), 123 + 456
        )
        self.assertEqual(
            self.decryptor.decrypt_raw(self.evaluator.sub(ct1, ct2)), 123 - 456
        )
        self.assertEqual(self.decryptor.decrypt_raw(self.evaluator.negate(ct1)), -123)

        pt1 = phe.Plaintext(self.ctx.get_schema(), 100)
        self.assertEqual(
            self.decryptor.decrypt_raw(self.evaluator.add(ct1, pt1)), 123 + 100
        )
        self.assertEqual(
            self.decryptor.decrypt_raw(self.evaluator.sub(ct1, pt1)), 123 - 100
        )

        # max case
        max_p = int(self.ctx.public_key().plaintext_bound()) - 1
        self.assertGreater(max_p, 2 ** 128)  # max_p is much, much larger than int128_t
        max_ct = self.encryptor.encrypt_raw(max_p)
        max_ct = self.evaluator.sub(
            max_ct, phe.Plaintext(self.ctx.get_schema(), 1)
        )
        self.assertEqual(self.decryptor.decrypt_raw(max_ct), max_p - 1)

    def test_add_inplace(self):
        sum = self.encryptor.encrypt_raw(0)
        for i in range(100):
            # Ciphertext + Ciphertext
            self.evaluator.add_inplace(sum, self.encryptor.encrypt_raw(i))
        # Ciphertext + Plaintext
        self.evaluator.add_inplace(sum, phe.Plaintext(self.ctx.get_schema(), 100))
        self.assertEqual(self.decryptor.decrypt_raw(sum), 5050)

    def test_encoding(self):
        edr = phe.IntegerEncoder(self.ctx.get_schema())
        self.assertTrue("IntegerEncoder" in str(edr))  # test ToString()

        # int case
        pt1 = edr.encode(123456)
        pt2 = edr.encode(987654)

        ct1 = self.encryptor.encrypt(pt1)
        ct2 = self.encryptor.encrypt(pt2)
        self.assertEqual(
            edr.decode(self.decryptor.decrypt(self.evaluator.add(ct1, ct2))),
            123456 + 987654,
        )
        self.assertEqual(
            edr.decode(self.decryptor.decrypt(self.evaluator.sub(ct1, ct2))),
            123456 - 987654,
        )
        cta = self.encryptor.encrypt_with_audit(pt1)
        print(cta[1])
        self.assertEqual(edr.decode(self.decryptor.decrypt(cta[0])), 123456)

        # float case
        edr = phe.FloatEncoder(self.ctx.get_schema())
        self.assertTrue("FloatEncoder" in str(edr))
        pt1 = edr.encode(123456.789)
        pt2 = edr.encode(987654.321)

        ct1 = self.encryptor.encrypt(pt1)
        ct2 = self.encryptor.encrypt(pt2)
        ct3 = self.evaluator.mul(self.evaluator.add(ct1, ct2), 2)
        self.assertEqual(
            edr.decode(self.decryptor.decrypt(ct3)), (123456.789 + 987654.321) * 2
        )

        # int128 case
        edr = phe.IntegerEncoder(self.ctx.get_schema(), 1)
        self.assertTrue("IntegerEncoder" in str(edr))
        n1 = 47509577600241629199431517033180053701
        pt1 = edr.encode(n1)
        self.assertEqual(edr.decode(pt1), n1)
        ct1 = self.encryptor.encrypt(pt1)
        self.assertEqual(edr.decode(self.decryptor.decrypt(ct1)), n1)

        n2 = -47509577600241629199431517033402775166
        pt2 = edr.encode(n2)
        self.assertEqual(edr.decode(pt2), n2)
        ct2 = self.encryptor.encrypt(pt2)
        self.assertEqual(
            edr.decode(self.decryptor.decrypt(self.evaluator.add(ct1, ct2))), -222721465
        )

        # bigint case
        edr = phe.BigintEncoder(self.ctx.get_schema())
        self.assertTrue("BigintEncoder" in str(edr))

        n1 = 12345
        pt1 = edr.encode(n1)
        self.assertEqual(edr.decode(pt1), n1)
        n2 = (
            4750957760024162919943151703318005370147509577600241629199431517033180053701
        )
        pt2 = edr.encode(n2)
        self.assertEqual(edr.decode(pt2), n2)
        n3 = (
            -4750957760024162919943151703318005370147509577600241629199431517033180053701
        )
        pt3 = edr.encode(n3)
        self.assertEqual(edr.decode(pt3), n3)
        ct1 = self.encryptor.encrypt(pt1)
        ct2 = self.encryptor.encrypt(pt2)
        ct3 = self.encryptor.encrypt(pt3)
        self.assertEqual(
            edr.decode(self.decryptor.decrypt(self.evaluator.add(ct1, ct2))), n1 + n2
        )
        self.assertEqual(
            edr.decode(self.decryptor.decrypt(self.evaluator.add(ct1, ct3))), n1 + n3
        )
        self.assertEqual(
            edr.decode(self.decryptor.decrypt(self.evaluator.add(ct2, ct3))), n2 + n3
        )

    def test_batch_encoding(self):
        bc = self.ctx.batch_encoder()
        pt1 = bc.encode(123, 456)
        pt2 = bc.encode(789, 101112)

        ct1 = self.encryptor.encrypt(pt1)
        ct2 = self.encryptor.encrypt(pt2)

        self.assertEqual(
            bc.decode(self.decryptor.decrypt(self.evaluator.add(ct1, ct2))),
            (123 + 789, 456 + 101112),
        )
        # Be caution with BatchEncoder's subtraction method.
        # It only works if every element in plaintext/ciphertext is a positive integer
        self.assertEqual(
            bc.decode(self.decryptor.decrypt(self.evaluator.sub(ct1, ct2))),
            (123 - 789, 456 - 101112),
        )


class ServerClientCase(unittest.TestCase):
    def test_pickle(self):
        import pickle

        # client: encrypt
        client_he = phe.setup(phe.SchemaType.ZPaillier, 2048)
        pk_buffer = pickle.dumps(client_he.public_key())

        ct1_buffer = pickle.dumps(client_he.encryptor().encrypt_raw(123))
        ct2_buffer = pickle.dumps(client_he.encryptor().encrypt_raw(456))

        # server: calc ct1 - ct2
        server_he = phe.setup(pickle.loads(pk_buffer))
        ct3 = server_he.evaluator().sub(
            pickle.loads(ct1_buffer), pickle.loads(ct2_buffer)
        )
        ct3_buffer = pickle.dumps(ct3)

        # client: decrypt
        ct_x = pickle.loads(ct3_buffer)
        self.assertEqual(client_he.decryptor().decrypt_raw(ct_x), 123 - 456)


if __name__ == "__main__":
    unittest.main()
