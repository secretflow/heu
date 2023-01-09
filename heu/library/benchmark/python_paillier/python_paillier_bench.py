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

# If you want to run this benchmark, please uncomment the following line.
# from phe import paillier
import google_benchmark as benchmark

K_TEST_SIZE = 10000
K_KEY_SIZE = 2048
K_RANDOM_SCALE = 8011


class Bencher:
    def __init__(self):
        self.public_key, self.private_key = paillier.generate_paillier_keypair(
            n_length=K_KEY_SIZE
        )
        self.pt_list = [x * K_RANDOM_SCALE for x in range(K_TEST_SIZE)]
        self.ct_sum = self.public_key.encrypt(0)
        self.ct_list = []

    def encrypt(self):
        self.ct_list = [self.public_key.encrypt(x) for x in self.pt_list]

    def add_cipher(self):
        for i in range(K_TEST_SIZE):
            self.ct_sum += self.ct_list[i]

    def sub_cipher(self):
        for i in range(K_TEST_SIZE):
            self.ct_sum -= self.ct_list[i]

    def add_int(self):
        for i in range(K_TEST_SIZE):
            self.ct_list[i] += i

    def mul_int(self):
        for i in range(K_TEST_SIZE):
            self.ct_list[i] *= i

    def decrypt(self):
        self.pt_list = [self.private_key.decrypt(x) for x in self.ct_list]


b = Bencher()


@benchmark.register
@benchmark.option.unit(benchmark.kMillisecond)
def paillier_encrypt(state):
    while state:
        b.encrypt()


@benchmark.register
@benchmark.option.unit(benchmark.kMillisecond)
def paillier_add_cipher(state):
    while state:
        b.add_cipher()


@benchmark.register
@benchmark.option.unit(benchmark.kMillisecond)
def paillier_sub_cipher(state):
    while state:
        b.sub_cipher()


@benchmark.register
@benchmark.option.unit(benchmark.kMillisecond)
def paillier_add_int(state):
    while state:
        b.add_int()


@benchmark.register
@benchmark.option.unit(benchmark.kMillisecond)
def paillier_mul_int(state):
    while state:
        b.mul_int()


@benchmark.register
@benchmark.option.unit(benchmark.kMillisecond)
def paillier_decrypt(state):
    while state:
        b.decrypt()


if __name__ == "__main__":
    benchmark.main()
