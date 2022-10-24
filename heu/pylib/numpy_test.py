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
import sys
import unittest

import numpy as np
import pickle

from heu import numpy as hnp
from heu import phe


class BasicCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kit = hnp.setup(phe.SchemaType.Mock, 2048)
        cls.encryptor = cls.kit.encryptor()
        cls.decryptor = cls.kit.decryptor()
        cls.evaluator = cls.kit.evaluator()

    def assert_array_equal(self, harr, nparr, edr=phe.BigintDecoder()):
        if isinstance(harr, hnp.CiphertextArray):
            harr = self.decryptor.decrypt(harr)

        harr = harr.to_numpy(edr)
        self.assertTrue(
            np.array_equal(harr, nparr), f"hnp is\n{harr}\nnumpy array is \n{nparr}"
        )

    def test_parse_and_str(self):
        harr = self.kit.array([[1, 2, 3], [4, 5, 6]])
        self.assertEqual(str(harr), "[[1 2 3]\n [4 5 6]]")
        harr = hnp.array([[1, 2, 3], [4, 5, 6]], self.kit.integer_encoder(scale=10))
        self.assertEqual(str(harr), "[[10 20 30]\n [40 50 60]]")

    def test_io(self):
        def do_test(input, encoder):
            # test raw parse
            harr = hnp.array(input, encoder)
            pyarr = harr.to_numpy(encoder)
            self.assertTrue(
                np.array_equal(pyarr, np.array(input)),
                f"hnp is {pyarr}, input is {input}",
            )

            # test works with numpy ndarray
            harr = hnp.array(np.array(input), encoder)
            pyarr = harr.to_numpy(encoder)
            self.assertTrue(
                np.array_equal(pyarr, np.array(input)),
                f"hnp is {pyarr}, input is {input}",
            )

        do_test(666, phe.IntegerEncoder(self.kit.get_schema()))
        do_test(666, phe.FloatEncoder(self.kit.get_schema()))
        do_test(666, phe.BigintEncoder(self.kit.get_schema()))

        do_test([1, 2, 3], phe.IntegerEncoder(self.kit.get_schema()))
        do_test([[1, 2, 3], [4, 5, 6]], phe.IntegerEncoder(self.kit.get_schema()))
        do_test([[10], [20]], phe.IntegerEncoder(self.kit.get_schema()))

        do_test([100.1], phe.FloatEncoder(self.kit.get_schema()))
        do_test([[1.1, 2.4], [3.6, 8]], phe.FloatEncoder(self.kit.get_schema()))

        do_test([1, 2, 3], phe.BigintEncoder(self.kit.get_schema()))
        do_test([[92233720368547758070]], phe.BigintEncoder(self.kit.get_schema()))
        do_test(
            [47509577600241629199431517033180053701475],
            phe.BigintEncoder(self.kit.get_schema()),
        )
        do_test(
            [[47509577600241629199431517033180053701475], [12]],
            phe.BigintEncoder(self.kit.get_schema()),
        )

        do_test([1, 2], phe.BatchEncoder(self.kit.get_schema()))
        do_test([[10, 11], [12, 13], [15, 16]], phe.BatchEncoder(self.kit.get_schema()))

    def test_encoder_parallel(self):
        edr = self.kit.integer_encoder()
        for idx in range(10):
            input = np.random.randint(-10000, 10000, (100, 100))
            harr = hnp.array(input, edr)
            self.assert_array_equal(harr, input, edr)

        edr = self.kit.float_encoder(scale=10 ** 8)
        for idx in range(50):
            input = np.random.rand(100, 100)
            harr = hnp.array(input, edr)
            pyarr = harr.to_numpy(edr)
            self.assertTrue(
                np.allclose(pyarr, input), f"hnp is \n{pyarr}\ninput is \n{input}"
            )

        edr = self.kit.bigint_encoder()
        for idx in range(50):
            input = np.random.randint(-10000, 10000, (100, 100))
            harr = hnp.array(input, edr)
            self.assert_array_equal(harr, input, edr)

        edr = self.kit.batch_encoder()
        for idx in range(50):
            input = np.random.randint(-10000, 10000, (5000, 2))
            harr = hnp.array(input, edr)
            self.assert_array_equal(harr, input, edr)

    def test_encrypt_with_audit(self):
        pt1 = self.kit.array([[1], [3]])
        ct1, audit = self.encryptor.encrypt_with_audit(pt1)
        self.assert_array_equal(self.decryptor.decrypt(ct1), np.array([[1], [3]]))

        buf = pickle.dumps(audit)
        a2 = pickle.loads(buf)
        self.assertEqual(a2.ndim, 2)
        self.assertEqual(tuple(a2.shape), (2, 1))
        self.assertGreater(len(a2[0, 0]), 1)

    def test_evaluate(self):
        pt1 = self.kit.array([[1, 2], [3, 4]])
        pt2 = self.kit.array([[4, 5], [6, 7]])
        self.assertEqual(pt2.rows, 2)
        self.assertEqual(pt2.cols, 2)
        self.assertEqual(tuple(pt2.shape), (2, 2))
        ct1 = self.encryptor.encrypt(pt1)
        ct2 = self.encryptor.encrypt(pt2)
        self.assertEqual(ct2.rows, 2)
        self.assertEqual(ct2.cols, 2)
        self.assertEqual(tuple(ct2.shape), (2, 2))

        # add
        ans = np.array([[5, 7], [9, 11]])
        pt3 = self.evaluator.add(pt1, pt2)
        buf = pickle.dumps(pt3)
        self.assert_array_equal(pickle.loads(buf), ans)
        ct3 = self.evaluator.add(ct1, pt2)
        buf = pickle.dumps(ct3)
        self.assert_array_equal(self.decryptor.decrypt(pickle.loads(buf)), ans)
        ct3 = self.evaluator.add(pt1, ct2)
        self.assert_array_equal(self.decryptor.decrypt(ct3), ans)
        ct3 = self.evaluator.add(ct1, ct2)
        self.assert_array_equal(self.decryptor.decrypt(ct3), ans)

        # sub
        ans = np.array([[-3, -3], [-3, -3]])
        pt3 = self.evaluator.sub(pt1, pt2)
        buf = pickle.dumps(pt3)
        self.assert_array_equal(pickle.loads(buf), ans)
        ct3 = self.evaluator.sub(ct1, pt2)
        buf = pickle.dumps(ct3)
        self.assert_array_equal(self.decryptor.decrypt(pickle.loads(buf)), ans)
        ct3 = self.evaluator.sub(pt1, ct2)
        self.assert_array_equal(self.decryptor.decrypt(ct3), ans)
        ct3 = self.evaluator.sub(ct1, ct2)
        self.assert_array_equal(self.decryptor.decrypt(ct3), ans)

        # mul
        ans = np.array([[4, 10], [18, 28]])
        pt3 = self.evaluator.mul(pt1, pt2)
        buf = pickle.dumps(pt3)
        self.assert_array_equal(pickle.loads(buf), ans)
        ct3 = self.evaluator.mul(ct1, pt2)
        buf = pickle.dumps(ct3)
        self.assert_array_equal(self.decryptor.decrypt(pickle.loads(buf)), ans)
        ct3 = self.evaluator.mul(pt1, ct2)
        self.assert_array_equal(self.decryptor.decrypt(ct3), ans)

        # matmul
        ans = np.array([[16, 19], [36, 43]])
        pt3 = self.evaluator.matmul(pt1, pt2)
        buf = pickle.dumps(pt3)
        self.assert_array_equal(pickle.loads(buf), ans)
        ct3 = self.evaluator.matmul(ct1, pt2)
        buf = pickle.dumps(ct3)
        self.assert_array_equal(self.decryptor.decrypt(pickle.loads(buf)), ans)
        ct3 = self.evaluator.matmul(pt1, ct2)
        self.assert_array_equal(self.decryptor.decrypt(ct3), ans)

        # sum
        pt3 = self.evaluator.sum(pt1)
        self.assertEqual(pt3, phe.Plaintext(self.kit.get_schema(), 10))
        ct3 = self.evaluator.sum(ct1)
        self.assertEqual(
            self.decryptor.phe.decrypt(ct3), phe.Plaintext(self.kit.get_schema(), 10)
        )
        pt3 = self.evaluator.sum(pt2)
        self.assertEqual(pt3, phe.Plaintext(self.kit.get_schema(), 22))
        ct3 = self.evaluator.sum(ct2)
        self.assertEqual(
            self.decryptor.phe.decrypt(ct3), phe.Plaintext(self.kit.get_schema(), 22)
        )

    def test_matmul(self):
        nparr1 = np.random.randint(-10000, 10000, (64,))
        harr1 = self.kit.array(nparr1)
        nparr2 = np.random.randint(-10000, 10000, (64, 256))
        harr2 = self.kit.array(nparr2)
        self.assert_array_equal(self.evaluator.matmul(harr1, harr2), nparr1 @ nparr2)

        # todo: impl transpose
        # harr2.transpose_inplace()
        # self.assert_array_equal(self.evaluator.matmul(harr2, harr1), nparr2.T @ nparr1)

        nparr2 = np.random.randint(-10000, 10000, (64,))
        harr2 = self.kit.array(nparr2)
        self.assert_array_equal(self.evaluator.matmul(harr1, harr2), nparr1 @ nparr2)

    def test_evaluate_parallel(self):
        nparr1 = np.random.randint(-10000, 10000, (100, 100))
        harr1 = self.kit.array(nparr1)
        nparr2 = np.random.randint(-10000, 10000, (100, 100))
        harr2 = self.encryptor.encrypt(self.kit.array(nparr2))

        # to_bytes
        self.assertEqual(nparr1.dtype, np.int64)
        self.assertEqual(harr1.to_bytes(8, sys.byteorder), nparr1.tobytes())

        # pt - pt
        self.assert_array_equal(self.evaluator.add(harr1, harr1), nparr1 * 2)
        self.assert_array_equal(self.evaluator.sub(harr1, harr1), nparr1 - nparr1)
        self.assert_array_equal(
            self.evaluator.mul(harr1, harr1), np.multiply(nparr1, nparr1)
        )
        self.assert_array_equal(self.evaluator.matmul(harr1, harr1), nparr1 @ nparr1)
        self.assertEqual(
            self.evaluator.sum(harr1),
            phe.Plaintext(self.kit.get_schema(), int(nparr1.sum())),
        )

        # ct - pt
        self.assert_array_equal((self.evaluator.add(harr2, harr1)), nparr2 + nparr1)
        self.assert_array_equal((self.evaluator.sub(harr2, harr1)), nparr2 - nparr1)
        self.assert_array_equal(
            (self.evaluator.mul(harr2, harr1)), np.multiply(nparr2, nparr1)
        )
        self.assert_array_equal((self.evaluator.matmul(harr2, harr1)), nparr2 @ nparr1)
        self.assertEqual(
            self.decryptor.decrypt(self.evaluator.sum(harr2)),
            phe.Plaintext(self.kit.get_schema(), int(nparr2.sum())),
        )

        # pt - ct
        self.assert_array_equal(self.evaluator.add(harr1, harr2), nparr1 + nparr2)
        self.assert_array_equal(self.evaluator.sub(harr1, harr2), nparr1 - nparr2)
        self.assert_array_equal(
            self.evaluator.mul(harr1, harr2), np.multiply(nparr1, nparr2)
        )
        self.assert_array_equal(self.evaluator.matmul(harr1, harr2), nparr1 @ nparr2)

        # ct - ct
        self.assert_array_equal(self.evaluator.add(harr2, harr2), nparr2 + nparr2)
        self.assert_array_equal(self.evaluator.sub(harr2, harr2), nparr2 - nparr2)

    def test_serialize(self):
        # client: encrypt and send
        pk_buffer = pickle.dumps(self.kit.public_key())
        pt_buffer = pickle.dumps(self.kit.array([[16, 19], [36, 43]]))
        ct_buffer = pickle.dumps(self.encryptor.encrypt(self.kit.array([1, 2])))

        # server: calc ct1 - ct2
        server_he = hnp.setup(pickle.loads(pk_buffer))
        pt = pickle.loads(pt_buffer)
        ct = pickle.loads(ct_buffer)
        res = server_he.evaluator().matmul(pt, ct)
        res_buffer = pickle.dumps(res)

        # client: decrypt
        res = pickle.loads(res_buffer)
        self.assert_array_equal(
            self.decryptor.decrypt(res),
            np.array([[16, 19], [36, 43]]) @ np.array([1, 2]),
        )

    def test_slice_get(self):
        nparr = np.arange(49).reshape((7, 7))
        harr = self.kit.array(nparr)

        self.assert_array_equal(harr[5:1, 1], nparr[5:1, 1])
        self.assert_array_equal(harr[4:, [1, 2, 2, 3]], nparr[4:, [1, 2, 2, 3]])
        self.assert_array_equal(harr[:4, (5,)], nparr[:4, (5,)])
        self.assert_array_equal(harr[-3:-1, (1, 3)], nparr[-3:-1, (1, 3)])
        self.assert_array_equal(harr[1:5:2, -1], nparr[1:5:2, -1])
        self.assert_array_equal(harr[::2, [-7, 5]], nparr[::2, [-7, 5]])
        self.assert_array_equal(harr[[1, 2, 3]], nparr[[1, 2, 3]])
        self.assert_array_equal(harr[1], nparr[1])
        self.assert_array_equal(harr[:], nparr[:])

        nparr = np.array([0, 1, 2, 3, 4, 5, 6, 7])
        harr = self.kit.array(nparr)
        self.assertEqual(tuple(harr.shape), (8,))
        self.assert_array_equal(harr[[1, 2, 3]], nparr[[1, 2, 3]])
        self.assert_array_equal(harr[:], nparr[:])

        self.assertEqual(int(harr[1]), nparr[1])
        self.assertEqual(int(harr[-1]), nparr[-1])
        self.assertEqual(int(harr[-7]), nparr[-7])

        # warning for numpy users: below slices are totally different:
        # heu-tensor returns a 2x2 matrix, while numpy returns 2-len vector
        # self.assert_array_equal(harr[[1, 2], [0, -1]], nparr[[1, 2], [0, -1]])

        # warning for numpy users: below slices are different
        # harr[(0,)]  ->  got 1d array: [0]
        # nparr[(0,)] ->  get scalar: 0

    def test_slice_set(self):
        # 2d <- 2d case
        nparr = np.arange(49).reshape((7, 7))
        harr = self.kit.array(nparr)

        nppatch = np.arange(16).reshape((4, 4))
        hpatch = self.kit.array(nppatch)
        nparr[1:5, [0, 1, 5, 6]] = nppatch
        harr[1:5, [0, 1, 5, 6]] = hpatch
        self.assert_array_equal(harr, nparr)
        nparr[[5, 6], 6:4:-1] = nparr[0:2, [3, 2]]
        harr[[5, 6], 6:4:-1] = harr[0:2, [3, 2]]
        self.assert_array_equal(harr, nparr)

        # 2d <- 1d case
        nppatch = np.arange(7)
        hpatch = self.kit.array(nppatch)
        nparr[0, :] = nppatch
        harr[0, :] = hpatch
        self.assert_array_equal(harr, nparr)

        nparr[:, 5] = nppatch
        harr[:, 5] = hpatch
        self.assert_array_equal(harr, nparr)

        # 2d <- scalar case
        nparr[1, 1] = 100
        harr[1, 1] = phe.Plaintext(self.kit.get_schema(), 100)
        self.assert_array_equal(harr, nparr)

        # 1d <- 1d case
        nparr = nparr[6, :]
        harr = harr[6, :]
        nppatch = np.arange(2)
        hpatch = self.kit.array(nppatch)
        nparr[[2, 5]] = nppatch
        harr[[2, 5]] = hpatch
        self.assert_array_equal(harr, nparr)

        # 1d <- scalar case
        nparr[-1] = 666
        harr[-1] = phe.Plaintext(self.kit.get_schema(), 666)
        self.assert_array_equal(harr, nparr)

    def test_ciphertext_slice_2d(self):
        nparr = np.arange(49).reshape((7, 7))
        harr = self.kit.array(nparr)
        carr = self.encryptor.encrypt(harr)
        # scalar case
        carr[6, 6] = self.encryptor.phe.encrypt(
            phe.Plaintext(self.kit.get_schema(), 666)
        )
        carr[6, 6] = self.encryptor.phe.encrypt_raw(1000)
        nparr[6, 6] = 1000
        # block case
        carr[[5, 6], 6:4:-1] = carr[0:2, [3, 2]]
        nparr[[5, 6], 6:4:-1] = nparr[0:2, [3, 2]]
        harr = self.decryptor.decrypt(carr)
        self.assert_array_equal(harr, nparr)
        # row case
        carr[:, -1] = carr[0, :]
        nparr[:, -1] = nparr[0, :]
        harr = self.decryptor.decrypt(carr)
        self.assert_array_equal(harr, nparr)
        # col case
        carr[-2, :] = carr[0, :]
        nparr[-2, :] = nparr[0, :]
        harr = self.decryptor.decrypt(carr)
        self.assert_array_equal(harr, nparr)

    def test_ciphertext_slice_1d(self):
        nparr = np.arange(100)
        harr = self.kit.array(nparr)
        carr = self.encryptor.encrypt(harr)
        # scalar case
        carr[-100] = self.encryptor.phe.encrypt_raw(1000)
        nparr[-100] = 1000
        # 1d case
        carr[1:3] = carr[98:]
        nparr[1:3] = nparr[98:]
        harr = self.decryptor.decrypt(carr)
        self.assert_array_equal(harr, nparr)

    def test_shape_and_random(self):
        m1 = hnp.random.randint(
            phe.Plaintext(self.kit.get_schema(), -100),
            phe.Plaintext(self.kit.get_schema(), 100),
            (10,),
        )
        self.assertEqual(m1.ndim, 1)
        self.assertEqual(tuple(m1.shape), (10,))

        buf = pickle.dumps(hnp.Shape(10, 20, 30))
        sp = pickle.loads(buf)[:2]
        self.assertTrue(isinstance(sp, hnp.Shape))
        m1 = hnp.random.randbits(self.kit.get_schema(), 2048, sp)
        self.assertEqual(m1.ndim, 2)
        self.assertEqual(tuple(m1.shape), (10, 20))


if __name__ == "__main__":
    unittest.main()
