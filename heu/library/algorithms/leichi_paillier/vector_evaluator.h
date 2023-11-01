// Copyright 2023 Polar Bear Tech (Xi 'an) Co., LTD.
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
#include "heu/library/algorithms/leichi_paillier/ciphertext.h"
#include "heu/library/algorithms/leichi_paillier/plaintext.h"
#include "heu/library/algorithms/leichi_paillier/public_key.h"
#include "heu/library/algorithms/leichi_paillier/secret_key.h"
#include "heu/library/algorithms/leichi_paillier/utils.h"
namespace heu::lib::algorithms::leichi_paillier {
    class Evaluator {
        private:
                PublicKey pk_;
        public:
            explicit Evaluator(const PublicKey& pk): pk_(std::move(pk)){}

            void Randomize(Span<Ciphertext> ct) const;

            std::vector<Ciphertext> Add(ConstSpan<Ciphertext> a,
                                        ConstSpan<Ciphertext> b) const;
            std::vector<Ciphertext> Add(ConstSpan<Ciphertext> a,
                                        ConstSpan<Plaintext> b) const;
            std::vector<Ciphertext> Add(ConstSpan<Plaintext> a,
                                        ConstSpan<Ciphertext> b) const;
            std::vector<Plaintext> Add(ConstSpan<Plaintext> a,
                                        ConstSpan<Plaintext> b) const;

            void AddInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const;
            void AddInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const;
            void AddInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

            std::vector<Ciphertext> Sub(ConstSpan<Ciphertext> a,
                                        ConstSpan<Ciphertext> b) const;
            std::vector<Ciphertext> Sub(ConstSpan<Ciphertext> a,
                                        ConstSpan<Plaintext> b) const;
            std::vector<Ciphertext> Sub(ConstSpan<Plaintext> a,
                                        ConstSpan<Ciphertext> b) const;
            std::vector<Plaintext> Sub(ConstSpan<Plaintext> a,
                                        ConstSpan<Plaintext> b) const;

            void SubInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const;
            void SubInplace(Span<Ciphertext> a, ConstSpan<Plaintext> p) const;
            void SubInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

            std::vector<Ciphertext> Mul(ConstSpan<Ciphertext> a,
                                        ConstSpan<Plaintext> b) const;
            std::vector<Ciphertext> Mul(ConstSpan<Plaintext> a,
                                        ConstSpan<Ciphertext> b) const;
            std::vector<Plaintext> Mul(ConstSpan<Plaintext> a,
                                        ConstSpan<Plaintext> b) const;

            void MulInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const;
            void MulInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const;

            std::vector<Ciphertext> Negate(ConstSpan<Ciphertext> a) const;
            void NegateInplace(Span<Ciphertext> a) const;
    };
}
